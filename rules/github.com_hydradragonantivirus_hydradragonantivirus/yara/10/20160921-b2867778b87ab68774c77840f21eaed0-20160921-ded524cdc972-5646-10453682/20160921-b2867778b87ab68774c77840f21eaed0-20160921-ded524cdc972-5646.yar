rule _20160921_b2867778b87ab68774c77840f21eaed0_20160921_ded524cdc972_5646 {
  meta:
    description = "datamaliciousorder - from files 20160921_b2867778b87ab68774c77840f21eaed0.js, 20160921_ded524cdc972424d0fa8254648795d71.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae46b7285b241d53af42d1248b27d7d1186f12901d6fc0284d48665a3b217777"
    hash2       = "09c4ea683259322d1696083646a9b96190b4796e8b3fdf91ba2bf4f6296afaa9"

  strings:
    $s1 = "\"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Lp\";})(),(func" ascii
    $s2 = "\"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Oh\";})(),(func" ascii
    $s3 = "\"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(fun" ascii
    $s4 = "00(){return \"Lp\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qj\"" ascii
    $s5 = "Kw\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Yi\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}