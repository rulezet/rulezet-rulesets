rule _20160921_09b25bffbd6bee308b23db7ad035cfd2_20160921_4787695fef44_3306 {
  meta:
    description = "datamaliciousorder - from files 20160921_09b25bffbd6bee308b23db7ad035cfd2.js, 20160921_4787695fef4453a16be881bbe0f96c1a.js, 20160921_8621b60975e0be691f97b2f5849011b9.js, 20160921_99369f59b90fb2df18b8570f0403febc.js, 20160921_a1c2a36f99325740dcba8c8ff770ac3f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0646df8d41668a96251f0443ca802dda915eadd4bc1fdb29b89948f4eb238893"
    hash2       = "6a11e3d64ee2711e84433d2b8035ce0dafbcffa760c2026e3cfe9ba310008f90"
    hash3       = "937753c3d12421c3fdd542dbca838c421a31dea2d960a14b5b2bd7617f8d3ec0"
    hash4       = "224e0a3dfee910c8afb81d7298f89c0b6e937cbd8062c03cedbe500c3dfe98a2"
    hash5       = "fd45dd180ae2e467969ca65317708ffe88d107b19f9f1b433b6c271c63c4fc6f"

  strings:
    $s1 = "i\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Uo\";})(),(function " ascii
    $s2 = "ction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){retur" ascii
    $s3 = "n f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"" ascii
    $s4 = "{return \"Sj\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(" ascii
    $s5 = "(){return \"OUx\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";}" ascii
    $s6 = "on f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}