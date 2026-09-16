rule sig_20160520_706b732e612ec06d617127baf32562e3 {
  meta:
    description = "datamaliciousorder - file 20160520_706b732e612ec06d617127baf32562e3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1013ed77793c5477cd035292c357d76f212d494d8a0eeb790c942648c7104f28"

  strings:
    $s1  = "function nPfTiHAz(oZzML) {var bUGdzeEv=wmttbLGsXaGJHYV[2];for(var EUGtc=0;EUGtc<oZzML;EUGtc++){Hjbdk+=bUGdzeEv.charAt(Math.floor" ascii
    $s2  = "function nPfTiHAz(oZzML) {var bUGdzeEv=wmttbLGsXaGJHYV[2];for(var EUGtc=0;EUGtc<oZzML;EUGtc++){Hjbdk+=bUGdzeEv.charAt(Math.floor" ascii
    $s3  = "bcPHsF.length;MDSVcNWQ++) {wvUhRaA+=MzaIv[bcPHsF[MDSVcNWQ]];}return wvUhRaA.substring(3,wvUhRaA.length);}" fullword ascii
    $s4  = "function MBRwVm(sQWztb){return sQWztb.ExpandEnvironmentStrings(wmttbLGsXaGJHYV[10])}" fullword ascii
    $s5  = "function sigwG(UUVffncW,bcPHsF,HtrOCLIVZ){MzaIv=UUVffncW.split(HtrOCLIVZ);wvUhRaA = wmttbLGsXaGJHYV[13];for(MDSVcNWQ=0;MDSVcNWQ<" ascii
    $s6  = "function OCqXhzw() {var xQoh=100000;var inZKWy = 100;return Math.random()*(xQoh-inZKWy)+inZKWy;}" fullword ascii
    $s7  = "try{nomFlDqHE(KNTeq[Tqbe], OCqXhzw() + wmttbLGsXaGJHYV[9], 1)}catch(e){}; " fullword ascii
    $s8  = "function UqQT(NsbdKK,mbwJWTj){ickH = wmttbLGsXaGJHYV[11].split(wmttbLGsXaGJHYV[12]);mbwJWTj.open(ickH[0]+ickH[2]+ickH[3], NsbdKK" ascii
    $s9  = "function GGTOd(jleDGpAr,PcIdd,YGbnaaULGU){jleDGpAr.open();jleDGpAr.type = 1;jleDGpAr.write(PcIdd);jleDGpAr.position = 0;jleDGpAr" ascii
    $s10 = "function GGTOd(jleDGpAr,PcIdd,YGbnaaULGU){jleDGpAr.open();jleDGpAr.type = 1;jleDGpAr.write(PcIdd);jleDGpAr.position = 0;jleDGpAr" ascii
    $s11 = "(Math.random()*bUGdzeEv.length));}return Hjbdk;}" fullword ascii
    $s12 = "function sigwG(UUVffncW,bcPHsF,HtrOCLIVZ){MzaIv=UUVffncW.split(HtrOCLIVZ);wvUhRaA = wmttbLGsXaGJHYV[13];for(MDSVcNWQ=0;MDSVcNWQ<" ascii
    $s13 = ", false);mbwJWTj.send();}" fullword ascii
    $s14 = "function UqQT(NsbdKK,mbwJWTj){ickH = wmttbLGsXaGJHYV[11].split(wmttbLGsXaGJHYV[12]);mbwJWTj.open(ickH[0]+ickH[2]+ickH[3], NsbdKK" ascii
    $s15 = "function nomFlDqHE(WRSrXBEVL,GJpSPzY,wqSUbUfB){" fullword ascii
    $s16 = "function AEWCA(sQWztb){return new ActiveXObject(sQWztb);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}