rule sig_20160315_5769392faa98a609f3e36c005aff4711 {
  meta:
    description = "datamaliciousorder - file 20160315_5769392faa98a609f3e36c005aff4711.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "88193ea2cff55dba53f405e5afc6797061ecc1988706bf9cf4bf416d1691d70f"

  strings:
    $s1 = "while (fmCwnSybz.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s2 = "function vhdQyUVmmhKhNl(fhNQFwPuuqiOmky){WshShell[vicKYFEjtQqttO](fhNQFwPuuqiOmky, 0, 0);}" fullword ascii
    $s3 = "VCNWkfIidw + YSlBuFvIOeNRCM + bYFrWVEiVY + QcltHyrlkgAYsN + rByUUZoJZT + nsuigDqfLiDmAn + jclLKce, false);" fullword ascii
    $s4 = "fmCwnSybz[NfhNdjtGNQys + ONWdB](fEQjuTsNmplg, nIZB + IdI + OaFsZvpThGRJYzm + YTIEPpRyYW + depWq + xhKLcltdpOS + rgOWkJXl + GQxot" ascii
    $s5 = "function RacfdzNwXv(n){return onEEBHuBuGTEt + DoduFhJiqcfcKB + Kgmz + rzCass + PlLOCaJyvkQZT + twMjh;}" fullword ascii
    $s6 = "var LWyqoSIck = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}