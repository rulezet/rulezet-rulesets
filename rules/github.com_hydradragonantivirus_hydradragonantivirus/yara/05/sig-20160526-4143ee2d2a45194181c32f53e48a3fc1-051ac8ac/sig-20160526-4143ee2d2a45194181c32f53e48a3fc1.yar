rule sig_20160526_4143ee2d2a45194181c32f53e48a3fc1 {
  meta:
    description = "datamaliciousorder - file 20160526_4143ee2d2a45194181c32f53e48a3fc1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e53b705608a4a5dc2814b35e5ef2ca0ce58d48929485aa5dc9303393b38e1eb"

  strings:
    $s1  = "function lZJzaxEIY(IfMvMSdulQWtK) {var yUHty = bHWnbBodUAlroNeHxPU.join(YdJPevNamNEcdQTj[0]);var LrLnPHZcY, iHJiHVHJujLevmsWzLcC" ascii
    $s2  = "function jIqcd(KovAMJY,CZSpDrLBBoiDHFChl){return KovAMJY.charAt(CZSpDrLBBoiDHFChl);}" fullword ascii
    $s3  = "erztB(LrLnPHZcY, iHJiHVHJujLevmsWzLcCi);else bYfAIAP += mfPXsAJDbcTrCIv(LrLnPHZcY, iHJiHVHJujLevmsWzLcCi, fgDrShaNpuTn);} while " ascii
    $s4  = "function mfPXsAJDbcTrCIv(gZQsCOZCiVMhozOnoPgvad,cOsDHigGYdQZ,nDBNC){return String.fromCharCode(gZQsCOZCiVMhozOnoPgvad,cOsDHigGYd" ascii
    $s5  = "function k(FdwjiwjqlDauniHExT){return String.fromCharCode(FdwjiwjqlDauniHExT);}" fullword ascii
    $s6  = "(BDxZRpaJbrLgaBCrZx < IfMvMSdulQWtK.length);return bYfAIAP;}" fullword ascii
    $s7  = "function hLswj(NrwFbbBTggNUyDZRTT,nxhMNauDfhPnK){return NrwFbbBTggNUyDZRTT.indexOf(nxhMNauDfhPnK);}" fullword ascii
    $s8  = "function mfPXsAJDbcTrCIv(gZQsCOZCiVMhozOnoPgvad,cOsDHigGYdQZ,nDBNC){return String.fromCharCode(gZQsCOZCiVMhozOnoPgvad,cOsDHigGYd" ascii
    $s9  = "function lZJzaxEIY(IfMvMSdulQWtK) {var yUHty = bHWnbBodUAlroNeHxPU.join(YdJPevNamNEcdQTj[0]);var LrLnPHZcY, iHJiHVHJujLevmsWzLcC" ascii
    $s10 = "function nasxKpKUMcZVlUsClerztB(lDmOpYuRCCN,ZzRydwYn){return String.fromCharCode(lDmOpYuRCCN,ZzRydwYn);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}