rule _20160921_016aab466e10a29b831eb85b27664027_20160921_0393cc83501a_984 {
  meta:
    description = "datamaliciousorder - from files 20160921_016aab466e10a29b831eb85b27664027.js, 20160921_0393cc83501a7f5f46bdb6e7b413461e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6a541dd7e97eedc43f6bcf89f007176352c81c1d1240a76218e73cf5bb3b171"
    hash2       = "89c5611205911dc22a002122b9f40afc236a2afc8f46d1c947520bc93cc73857"

  strings:
    $s1  = "urn \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TRc\";})()," ascii
    $s2  = "rn \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(" ascii
    $s3  = "000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"RPt" ascii
    $s4  = "GGn\";})(),(function f000(){return \"Ut\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"XTn\";})(),(functi" ascii
    $s5  = "tion f000(){return \"Qz\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s6  = "{return \"WIj\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qz\";})(" ascii
    $s7  = "(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qz\";" ascii
    $s8  = "{return \"WIj\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"RPt\";})" ascii
    $s9  = "0(){return \"RPt\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TRc\"" ascii
    $s10 = "g\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(functio" ascii
    $s11 = ";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TRc\";})(),(function f0" ascii
    $s12 = "{return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})()" ascii
    $s13 = "),(function f000(){return \"TKl\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(function f000(" ascii
    $s14 = ")(),(function f000(){return \"Mu\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"KXg\";})(),(function f000" ascii
    $s15 = " \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Yi\";})(),(func" ascii
    $s16 = "n \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"RPt\";})(),(fu" ascii
    $s17 = "n \"GGn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Yi\";})(),(fun" ascii
    $s18 = "n \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Zj\";})(),(fun" ascii
    $s19 = "n \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"KXg\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}