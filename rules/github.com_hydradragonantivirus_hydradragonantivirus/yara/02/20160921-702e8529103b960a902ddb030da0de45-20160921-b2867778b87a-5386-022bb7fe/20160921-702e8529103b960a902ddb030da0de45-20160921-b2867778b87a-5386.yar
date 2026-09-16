rule _20160921_702e8529103b960a902ddb030da0de45_20160921_b2867778b87a_5386 {
  meta:
    description = "datamaliciousorder - from files 20160921_702e8529103b960a902ddb030da0de45.js, 20160921_b2867778b87ab68774c77840f21eaed0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf8ba9fdbe4ef225cb892f7294538710b1dd7e8bc4e280897680c51e03816d1c"
    hash2       = "ae46b7285b241d53af42d1248b27d7d1186f12901d6fc0284d48665a3b217777"

  strings:
    $s1 = "f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"UE" ascii
    $s2 = "rn \"IAa\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s3 = "tion f000(){return \"Sv\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s4 = "n f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"" ascii
    $s5 = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"ZFe\";})(),(function f0" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}