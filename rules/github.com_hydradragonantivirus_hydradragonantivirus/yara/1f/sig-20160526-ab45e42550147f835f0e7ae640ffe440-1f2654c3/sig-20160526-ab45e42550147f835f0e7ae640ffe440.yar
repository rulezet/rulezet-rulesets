rule sig_20160526_ab45e42550147f835f0e7ae640ffe440 {
  meta:
    description = "datamaliciousorder - file 20160526_ab45e42550147f835f0e7ae640ffe440.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f4ef99ad1028c678f2774fa54a769d973a39f0e47cb72e25e10776a17e1f8a1c"

  strings:
    $s1  = "function icWTFSNnqMqLTl(ljDxtDXccFlaW) {var cNJVqEmsivPusASzKCWIZDt = LFuVYIIHd.join(uyasBwPjOVc[0]);var WzefNnefOYJqRxLRmzsWZQc" ascii
    $s2  = "f;frxvDTAjIusEZpddndLlH = xusVtYwgviLdRRxIESWE & 0xff;if (dXKBFawVvUvUOM == (861 + Math.round((Math.pow(Math.sin(101), 2) + Math" ascii
    $s3  = ".pow(Math.cos(101), 2) - 1))-797)) KQlTlqnznuEDrmTMFknIgLmm += mu(WzefNnefOYJqRxLRmzsWZQc);else if (OJgUUgZxneySxMtGXIgrP == (74" ascii
    $s4  = "function ScfZsOVtXhylu(faIAtZVQTKlrKhxF,IpcdCWbQcTCiVRDrkGIjw){return faIAtZVQTKlrKhxF.charAt(IpcdCWbQcTCiVRDrkGIjw);}" fullword ascii
    $s5  = "function weylZgBBtDtPWCUwWwg(lPEfQBRXG,FsbZhmHNhMgOtjQlvS){return String.fromCharCode(lPEfQBRXG,FsbZhmHNhMgOtjQlvS);}" fullword ascii
    $s6  = "Wwg(WzefNnefOYJqRxLRmzsWZQc, xUQQDh);else KQlTlqnznuEDrmTMFknIgLmm += NkLhdRc(WzefNnefOYJqRxLRmzsWZQc, xUQQDh, frxvDTAjIusEZpddn" ascii
    $s7  = "function icWTFSNnqMqLTl(ljDxtDXccFlaW) {var cNJVqEmsivPusASzKCWIZDt = LFuVYIIHd.join(uyasBwPjOVc[0]);var WzefNnefOYJqRxLRmzsWZQc" ascii
    $s8  = "function NkLhdRc(uzOroNMVEphajC,fVvBdSXxEuIw,swSqRlgxQEFJa){return String.fromCharCode(uzOroNMVEphajC,fVvBdSXxEuIw,swSqRlgxQEFJa" ascii
    $s9  = "function npZFTSmZzGTXFSzIrgxx(KLrezNamNhwDyMEyrKa,vFEniXXvAKmhqeV){return KLrezNamNhwDyMEyrKa.indexOf(vFEniXXvAKmhqeV);}" fullword ascii
    $s10 = "function mu(dmcpiXFZAAiupb){return String.fromCharCode(dmcpiXFZAAiupb);}" fullword ascii
    $s11 = "dLlH);} while (oXLVrlheqJixQsYgmQdH < ljDxtDXccFlaW.length);return KQlTlqnznuEDrmTMFknIgLmm;}" fullword ascii
    $s12 = "function NkLhdRc(uzOroNMVEphajC,fVvBdSXxEuIw,swSqRlgxQEFJa){return String.fromCharCode(uzOroNMVEphajC,fVvBdSXxEuIw,swSqRlgxQEFJa" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}