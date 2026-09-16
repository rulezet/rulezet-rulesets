rule _20160921_98f234a378a6dd4e51c1730a4a700647_20160921_9aa040f4b657_3999 {
  meta:
    description = "datamaliciousorder - from files 20160921_98f234a378a6dd4e51c1730a4a700647.js, 20160921_9aa040f4b657816cc001fcf9a33be586.js, 20160921_d7492227e681b1689bfc5442a91a169e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "67d0e50d586bb8bcc6b12ccab848f1a72b3a329ddaa0c7f45ea3661082887c8d"
    hash2       = "06edaae6cd03c231dca115449fcaf6955b5f70df34983f02383296a412f73538"
    hash3       = "63aa129680edf69c72e8f077be5e8562f041fa0b0c7e63a8a9b219c23749b135"

  strings:
    $s1 = "on f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"" ascii
    $s2 = "000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Wb\"" ascii
    $s3 = "(){return \"Oe\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})" ascii
    $s4 = "000(){return \"Vj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";" ascii
    $s5 = "(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"KXg\";})(),(function f000(" ascii
    $s6 = "XTn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}