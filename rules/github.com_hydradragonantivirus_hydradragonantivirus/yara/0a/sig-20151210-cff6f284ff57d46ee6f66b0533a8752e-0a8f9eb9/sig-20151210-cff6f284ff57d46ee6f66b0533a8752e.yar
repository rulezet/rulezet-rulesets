rule sig_20151210_cff6f284ff57d46ee6f66b0533a8752e {
  meta:
    description = "datamaliciousorder - file 20151210_cff6f284ff57d46ee6f66b0533a8752e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5448122ce2fb5ebe02a96f3f1d33ec8f3fd1ae864cd104b21ec9f24cdfc00d17"

  strings:
    $s1  = "function iGaTBEb(DgKziSJLbjeqCQqSrMDXJCLFtMQSEZpVtYsn) {return !isNaN(parseFloat(DgKziSJLbjeqCQqSrMDXJCLFtMQSEZpVtYsn)) && isFin" ascii
    $s2  = "function iGaTBEb(DgKziSJLbjeqCQqSrMDXJCLFtMQSEZpVtYsn) {return !isNaN(parseFloat(DgKziSJLbjeqCQqSrMDXJCLFtMQSEZpVtYsn)) && isFin" ascii
    $s3  = "function vcgQRymLJOOYjPBBdJRngpaItaJhDqTmunssdEkWUIUksaPcdPwjLU(uPFrEyvRJmfRU,SwAlAgrBqzOvTL){ return agVqpQgldODcm[Otyhe(uPFrEy" ascii
    $s4  = "BqPfyXs=(-302+302)/543;while(true){if(BqPfyXs>=(68863+129)/539){break;}agVqpQgldODcm[BqPfyXs]=String.fromCharCode(BqPfyXs);BqPfy" ascii
    $s5  = "function hskJiXDqPkK(wxymDuTl,FOpOZI){return wxymDuTl.split(FOpOZI)}" fullword ascii
    $s6  = "function rsFufhjeyGzeHGRVG(HeHhK){eeIemlMdyVK= '';for(qwsPFdindtn=(-707+707)/809; qwsPFdindtn < (-6+854)/424; qwsPFdindtn++) {Rm" ascii
    $s7  = "function vcgQRymLJOOYjPBBdJRngpaItaJhDqTmunssdEkWUIUksaPcdPwjLU(uPFrEyvRJmfRU,SwAlAgrBqzOvTL){ return agVqpQgldODcm[Otyhe(uPFrEy" ascii
    $s8  = "XjGROlO[qwsPFdindtn]=(-881+881)/314; while(true) { if(RmXjGROlO[qwsPFdindtn] > HeHhK[qwsPFdindtn].length-(55+11)/66) { break; } " ascii
    $s9  = "function rsFufhjeyGzeHGRVG(HeHhK){eeIemlMdyVK= '';for(qwsPFdindtn=(-707+707)/809; qwsPFdindtn < (-6+854)/424; qwsPFdindtn++) {Rm" ascii
    $s10 = "function Otyhe(fWmaaNJhwtO,CdIipOdaANdcG,uEcFXcqs){KxKT=parseInt(fWmaaNJhwtO,CdIipOdaANdcG);iufAM=KxKT.toString(uEcFXcqs);return" ascii
    $s11 = "function Otyhe(fWmaaNJhwtO,CdIipOdaANdcG,uEcFXcqs){KxKT=parseInt(fWmaaNJhwtO,CdIipOdaANdcG);iufAM=KxKT.toString(uEcFXcqs);return" ascii
    $s12 = "BqPfyXs=(-302+302)/543;while(true){if(BqPfyXs>=(68863+129)/539){break;}agVqpQgldODcm[BqPfyXs]=String.fromCharCode(BqPfyXs);BqPfy" ascii
    $s13 = " iufAM;}function fbvJEyDnQtBOjUI(otbDqLEyZXuntBwIj){eval(otbDqLEyZXuntBwIj)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}