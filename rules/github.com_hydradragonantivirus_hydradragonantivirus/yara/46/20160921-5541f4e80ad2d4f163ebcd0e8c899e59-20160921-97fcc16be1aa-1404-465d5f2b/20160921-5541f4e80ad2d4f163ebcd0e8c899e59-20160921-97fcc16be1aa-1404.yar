rule _20160921_5541f4e80ad2d4f163ebcd0e8c899e59_20160921_97fcc16be1aa_1404 {
  meta:
    description = "datamaliciousorder - from files 20160921_5541f4e80ad2d4f163ebcd0e8c899e59.js, 20160921_97fcc16be1aae58b311e71df667be641.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "615edf37483855ab2b78dd87e38795245913e5fc6efc9bc47d9e698132792739"
    hash2       = "2459214bba37a40478bc984d75c7b1ababcbf0d17eeabe32578555058bdac21f"

  strings:
    $s1  = "rn \"GGn\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Qj\";})(),(f" ascii
    $s2  = "function f000(){return \"Nv\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"Vj\";})(),(function f000(){ret" ascii
    $s3  = ")(),(function f000(){return \"PTs\";})(),(function f000(){return \"Fs\";})(),(function f000(){return \"Br\";})(),(function f000(" ascii
    $s4  = "n\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Lo\";})(),(function" ascii
    $s5  = " \"Br\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Br\";})(),(functi" ascii
    $s6  = "ion f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTs\";})(),(function f000(){return " ascii
    $s7  = "ction f000(){return \"Br\";})(),(function f000(){return \"Fs\";})(),(function f000(){return \"HJm\";})(),(function f000(){return" ascii
    $s8  = "(){return \"MBb\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Br\";})" ascii
    $s9  = "n \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s10 = "\"SEo\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"WIj\";})(),(func" ascii
    $s11 = "000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"NYh" ascii
    $s12 = "rn \"Sq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(f" ascii
    $s13 = ",(function f000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Sq\";})(),(function f000(){" ascii
    $s14 = "{return \"Nv\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"GGn\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}