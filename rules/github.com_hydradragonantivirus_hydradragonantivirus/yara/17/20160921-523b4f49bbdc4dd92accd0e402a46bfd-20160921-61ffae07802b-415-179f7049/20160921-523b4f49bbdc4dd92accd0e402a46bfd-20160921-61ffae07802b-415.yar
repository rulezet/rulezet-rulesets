rule _20160921_523b4f49bbdc4dd92accd0e402a46bfd_20160921_61ffae07802b_415 {
  meta:
    description = "datamaliciousorder - from files 20160921_523b4f49bbdc4dd92accd0e402a46bfd.js, 20160921_61ffae07802bf5013fbbf8f137c827c3.js, 20160921_f850d4c4897a9bd959014c9fc7d18a6b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f9f8d6d5ec4629c30430c47234803f947380ed84d76b2caa48ab30caee473c3"
    hash2       = "d1b5dbd3605683fd0b3b1dc802f1048401a8db23070c8205273f5c5ab6c5133c"
    hash3       = "d8fc3e7e41c34088a452b3b6538d4581b58ba00503833e565b195ce374f63b54"

  strings:
    $s1  = "(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"NBs\";" ascii
    $s2  = "),(function f000(){return \"Yz\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"MDb\";})(),(function f000(){" ascii
    $s3  = "000(){return \"IAa\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb" ascii
    $s4  = "0(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"GGn" ascii
    $s5  = "),(function f000(){return \"MDb\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Sj\";})(),(function f000(){" ascii
    $s6  = " \"Nx\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Mc\";})(),(func" ascii
    $s7  = " f000(){return \"Br\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"SG" ascii
    $s8  = "on f000(){return \"Mc\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"MDb\";})(),(function f000(){return " ascii
    $s9  = "000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"MBb" ascii
    $s10 = " \"Br\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Br\";})(),(functi" ascii
    $s11 = "){return \"Oe\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Br\";})(" ascii
    $s12 = "(),(function f000(){return \"MDb\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"ZFe\";})(),(function f000(" ascii
    $s13 = " \"RLk\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"XTn\";})(),(fun" ascii
    $s14 = ";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Br\";})(),(function f000" ascii
    $s15 = "nction f000(){return \"Yi\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Sj\";})(),(function f000(){retur" ascii
    $s16 = "n\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Yz\";})(),(function f" ascii
    $s17 = "eturn \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Yz\";})()," ascii
    $s18 = "),(function f000(){return \"Qz\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"ZIi\";})(),(function f000()" ascii
    $s19 = "000(){return \"Oh\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj" ascii
    $s20 = "){return \"Br\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Mc\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}