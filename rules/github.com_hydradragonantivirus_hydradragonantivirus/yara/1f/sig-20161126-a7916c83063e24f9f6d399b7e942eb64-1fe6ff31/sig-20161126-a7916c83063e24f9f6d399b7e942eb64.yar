rule sig_20161126_a7916c83063e24f9f6d399b7e942eb64 {
  meta:
    description = "datamaliciousorder - file 20161126_a7916c83063e24f9f6d399b7e942eb64.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a523076ba2418429b40f2a6c2b02da93023597c0232730548b80e98c763dffcc"

  strings:
    $s1 = "var ofjulwe93 = new Function([\"retu\", '#', '#', '#', '#', '#'].hvucqi() + [\"rn A\", '#', '#', '#', '#', '#'].hvucqi() + [\"ct" ascii
    $s2 = "var ofjulwe93 = new Function([\"retu\", '#', '#', '#', '#', '#'].hvucqi() + [\"rn A\", '#', '#', '#', '#', '#'].hvucqi() + [\"ct" ascii
    $s3 = "Array.prototype.hvucqi = new Function(\"var dkyhxyq = this; return  dkyhxyq[0];\");" fullword ascii
    $s4 = "switch (toko9[[ugumva][0]] > 4) {" fullword ascii

  condition:
    uint16(0) == 0x7241 and
    all of them
}