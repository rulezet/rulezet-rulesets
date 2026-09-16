rule _20160921_331df381948e6d95c6a9496aeda63d16_20160921_86f41d8c8324_4879 {
  meta:
    description = "datamaliciousorder - from files 20160921_331df381948e6d95c6a9496aeda63d16.js, 20160921_86f41d8c83240a68770674107f15f162.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "74d3e5ca6efd3e26128cb4a5ab3009003c70f505b353304608d74dfd028df0d7"
    hash2       = "56a4c0b8742284d9e8907df1b8d73d9c73ee82bc9595e88d869c555afd77312d"

  strings:
    $s1 = "ion f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return " ascii
    $s2 = "f000(){return \"Qz\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj" ascii
    $s3 = "{return \"Do\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(" ascii
    $s4 = " \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Do\";})(),(func" ascii
    $s5 = "eturn \"GGn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Zj\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}