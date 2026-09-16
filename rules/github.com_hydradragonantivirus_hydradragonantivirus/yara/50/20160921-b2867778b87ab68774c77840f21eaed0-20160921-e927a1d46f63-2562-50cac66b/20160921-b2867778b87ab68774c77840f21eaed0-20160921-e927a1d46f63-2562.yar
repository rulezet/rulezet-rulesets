rule _20160921_b2867778b87ab68774c77840f21eaed0_20160921_e927a1d46f63_2562 {
  meta:
    description = "datamaliciousorder - from files 20160921_b2867778b87ab68774c77840f21eaed0.js, 20160921_e927a1d46f63fcc6ccb740b1d71293f3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae46b7285b241d53af42d1248b27d7d1186f12901d6fc0284d48665a3b217777"
    hash2       = "a681cf04685052da0d288a0246e49880f34a91dc46ff378f7cf1859ae526c1ef"

  strings:
    $s1 = "00(){return \"Wy\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"UEg\";" ascii
    $s2 = "0(){return \"SEo\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\"" ascii
    $s3 = "nction f000(){return \"OUx\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"NYh\";})(),(function f000(){ret" ascii
    $s4 = "nction f000(){return \"Vu\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return" ascii
    $s5 = "\"DIa\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"BIj\";})(),(fun" ascii
    $s6 = "(function f000(){return \"QDg\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"BQb\";})(),(function f000(){r" ascii
    $s7 = "){return \"DYx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"OUx\";" ascii
    $s8 = "m\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Mc\";})(),(function f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}