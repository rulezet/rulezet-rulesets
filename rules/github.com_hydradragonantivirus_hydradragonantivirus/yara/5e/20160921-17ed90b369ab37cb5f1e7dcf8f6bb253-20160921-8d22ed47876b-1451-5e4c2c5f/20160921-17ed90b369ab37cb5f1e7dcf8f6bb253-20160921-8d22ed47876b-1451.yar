rule _20160921_17ed90b369ab37cb5f1e7dcf8f6bb253_20160921_8d22ed47876b_1451 {
  meta:
    description = "datamaliciousorder - from files 20160921_17ed90b369ab37cb5f1e7dcf8f6bb253.js, 20160921_8d22ed47876b303a1415a88483556238.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81de0ae14e0c288b697a0e3c7f3ced9b68b8377e75dff5322d654841e642a8a7"
    hash2       = "666a3f8cd9a533a20e260aad6bcb18265aad030f6f978c4cc3c9da557262f1ae"

  strings:
    $s1  = "(),(function f000(){return \"MJq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Ml\";})(),(function f000(" ascii
    $s2  = "(function f000(){return \"Nx\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(function f000(){r" ascii
    $s3  = "00(){return \"TKl\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"DAp" ascii
    $s4  = "n f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"" ascii
    $s5  = " \"Br\";})(),(function f000(){return \"Yx\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"Wh\";})(),(functi" ascii
    $s6  = "rn \"Tn\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"YTp\";})(),(fun" ascii
    $s7  = "return \"Km\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Oe\";})()," ascii
    $s8  = "00(){return \"Mt\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Yz\";" ascii
    $s9  = "00(){return \"PTi\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Uo\"" ascii
    $s10 = "nction f000(){return \"Wy\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s11 = "return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Rh\";})()" ascii
    $s12 = "nction f000(){return \"XTn\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"OUx\";})(),(function f000(){ret" ascii
    $s13 = "t\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"EZu\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}