rule _20160921_331df381948e6d95c6a9496aeda63d16_20160921_4d4f88bcbe1d_3613 {
  meta:
    description = "datamaliciousorder - from files 20160921_331df381948e6d95c6a9496aeda63d16.js, 20160921_4d4f88bcbe1d7c27849018b54d3401d0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "74d3e5ca6efd3e26128cb4a5ab3009003c70f505b353304608d74dfd028df0d7"
    hash2       = "8c037da0756f2e03c3daf2ada4f7a359fd0381e67b8eccb57785222e669ac983"

  strings:
    $s1 = "ction f000(){return \"PTi\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Nx\";})(),(function f000(){retur" ascii
    $s2 = "eturn \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TKl\";})(" ascii
    $s3 = "eturn \"MJq\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"PTi\";})()" ascii
    $s4 = "f000(){return \"OUx\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TK" ascii
    $s5 = ";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"ZGq\";})(),(function f0" ascii
    $s6 = "ction f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Vu\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}