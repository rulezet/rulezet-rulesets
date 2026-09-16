rule sig_20151209_5e61d6de3a393edcd16665c550850a8c {
  meta:
    description = "datamaliciousorder - file 20151209_5e61d6de3a393edcd16665c550850a8c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "47f05ee33798c7ca513634a5379866e603cd0267db693d7a231da4ddf9401181"

  strings:
    $s1  = "function kyaRQsN(OgAJZbACRHUwnSvgsKhpDefbxLKyIXimIIbw) {return !isNaN(parseFloat(OgAJZbACRHUwnSvgsKhpDefbxLKyIXimIIbw)) && isFin" ascii
    $s2  = "function kyaRQsN(OgAJZbACRHUwnSvgsKhpDefbxLKyIXimIIbw) {return !isNaN(parseFloat(OgAJZbACRHUwnSvgsKhpDefbxLKyIXimIIbw)) && isFin" ascii
    $s3  = "AvRvbTTb[lImncrSCvnb]=(-315+315)/168; while(true) { if(HAvRvbTTb[lImncrSCvnb] > jmYQM[lImncrSCvnb].length-(418+289)/707) { break" ascii
    $s4  = "function VekAfChmTWRLxyUxk(jmYQM){LCPClgtSVGU= '';for(lImncrSCvnb=(-116+116)/69; lImncrSCvnb < (1005+209)/607; lImncrSCvnb++) {H" ascii
    $s5  = "function wvTeU(vCHiYuCJpcw,TKUUNVJzRsIuV,XoRNVbDp){CEKK=parseInt(vCHiYuCJpcw,TKUUNVJzRsIuV);ioQIY=CEKK.toString(XoRNVbDp);return" ascii
    $s6  = " ioQIY;}function PvuHOIHNvKuTfPB(tWjPOAgEWePkcSllm){eval(tWjPOAgEWePkcSllm)}" fullword ascii
    $s7  = "function bGSNSVxqoMFSYglJPylLaTVtrmHEcHfBcqyrRjGWiSPztdDRthmwzj(MYReGFSbOEymW,DsHOWtXmOTrptY){ return GydbM[wvTeU(MYReGFSbOEymW[" ascii
    $s8  = "function bGSNSVxqoMFSYglJPylLaTVtrmHEcHfBcqyrRjGWiSPztdDRthmwzj(MYReGFSbOEymW,DsHOWtXmOTrptY){ return GydbM[wvTeU(MYReGFSbOEymW[" ascii
    $s9  = "function rNfgKinhmtx(bHckgxnm,qdnpxE){return bHckgxnm.split(qdnpxE)}" fullword ascii
    $s10 = "+;}} return LCPClgtSVGU}" fullword ascii
    $s11 = "function VekAfChmTWRLxyUxk(jmYQM){LCPClgtSVGU= '';for(lImncrSCvnb=(-116+116)/69; lImncrSCvnb < (1005+209)/607; lImncrSCvnb++) {H" ascii
    $s12 = "function wvTeU(vCHiYuCJpcw,TKUUNVJzRsIuV,XoRNVbDp){CEKK=parseInt(vCHiYuCJpcw,TKUUNVJzRsIuV);ioQIY=CEKK.toString(XoRNVbDp);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}