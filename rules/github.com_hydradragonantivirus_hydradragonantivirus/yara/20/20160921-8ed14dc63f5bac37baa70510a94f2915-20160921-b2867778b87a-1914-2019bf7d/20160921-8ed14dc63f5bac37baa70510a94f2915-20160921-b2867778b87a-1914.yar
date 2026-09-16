rule _20160921_8ed14dc63f5bac37baa70510a94f2915_20160921_b2867778b87a_1914 {
  meta:
    description = "datamaliciousorder - from files 20160921_8ed14dc63f5bac37baa70510a94f2915.js, 20160921_b2867778b87ab68774c77840f21eaed0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e01d4cea60f1c16b2fc3a28a98b5ad4d421b0c4e8e5f757805e98a1436a9fadd"
    hash2       = "ae46b7285b241d53af42d1248b27d7d1186f12901d6fc0284d48665a3b217777"

  strings:
    $s1  = "return \"Br\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})()," ascii
    $s2  = " f000(){return \"Lo\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GG" ascii
    $s3  = "00(){return \"DYs\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\"" ascii
    $s4  = "eturn \"MKa\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MKa\";})()];" fullword ascii
    $s5  = " \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(fu" ascii
    $s6  = "ion f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Nx\";})(),(function f000(){return " ascii
    $s7  = " f000(){return \"SEo\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"" ascii
    $s8  = "function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Mt\";})(),(function f000(){ret" ascii
    $s9  = "{return \"Vj\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(" ascii
    $s10 = "rn \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}