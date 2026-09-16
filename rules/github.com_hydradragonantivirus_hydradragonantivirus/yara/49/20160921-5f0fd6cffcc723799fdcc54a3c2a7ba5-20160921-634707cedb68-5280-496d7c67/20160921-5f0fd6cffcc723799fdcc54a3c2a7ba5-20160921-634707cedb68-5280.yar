rule _20160921_5f0fd6cffcc723799fdcc54a3c2a7ba5_20160921_634707cedb68_5280 {
  meta:
    description = "datamaliciousorder - from files 20160921_5f0fd6cffcc723799fdcc54a3c2a7ba5.js, 20160921_634707cedb68c58923df5bdbd700c1bc.js, 20160921_da4ec6dae2eccab30a5e229082e39a40.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f215df78f73f84c8424edec81b4a9e43c0b766f9010caf095301b900f03214fb"
    hash2       = "152351bec2365a464c735883af22dfe66d59686fad11d1304e9e19accdb6f596"
    hash3       = "3bcc141cccd11dbba68b7c117d19efcd0472cb34792cc4b7e6c3d54e8a0929cc"

  strings:
    $s1 = "on f000(){return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"" ascii
    $s2 = "n \"WIj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(fu" ascii
    $s3 = "(function f000(){return \"Kw\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qz\";})(),(function f000(){ret" ascii
    $s4 = "n \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"KXg\";})(),(fun" ascii
    $s5 = ",(function f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}