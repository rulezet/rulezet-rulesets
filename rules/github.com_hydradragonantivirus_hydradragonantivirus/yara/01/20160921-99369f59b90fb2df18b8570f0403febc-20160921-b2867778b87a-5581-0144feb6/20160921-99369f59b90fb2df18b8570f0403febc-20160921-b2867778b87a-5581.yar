rule _20160921_99369f59b90fb2df18b8570f0403febc_20160921_b2867778b87a_5581 {
  meta:
    description = "datamaliciousorder - from files 20160921_99369f59b90fb2df18b8570f0403febc.js, 20160921_b2867778b87ab68774c77840f21eaed0.js, 20160921_cebdb99ce2e54d24acef5b8ee0096562.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "224e0a3dfee910c8afb81d7298f89c0b6e937cbd8062c03cedbe500c3dfe98a2"
    hash2       = "ae46b7285b241d53af42d1248b27d7d1186f12901d6fc0284d48665a3b217777"
    hash3       = "87071d18d308dc7717dabe03dc0d11efe7ee7231e95d9fca71e480f5f2430f7d"

  strings:
    $s1 = "tion f000(){return \"MDb\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Sv\";})(),(function f000(){return " ascii
    $s2 = "(){return \"QDg\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Iq\";})" ascii
    $s3 = "})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"MBb\";})(),(function f00" ascii
    $s4 = "(),(function f000(){return \"Qa\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"MJq\";})(),(function f000(" ascii
    $s5 = "turn \"BMj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"RLk\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}