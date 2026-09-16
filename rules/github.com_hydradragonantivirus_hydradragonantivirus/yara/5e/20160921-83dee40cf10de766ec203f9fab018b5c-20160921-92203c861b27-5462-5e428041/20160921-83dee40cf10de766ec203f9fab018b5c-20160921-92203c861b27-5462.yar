rule _20160921_83dee40cf10de766ec203f9fab018b5c_20160921_92203c861b27_5462 {
  meta:
    description = "datamaliciousorder - from files 20160921_83dee40cf10de766ec203f9fab018b5c.js, 20160921_92203c861b27f106aadc39fdc2b4c6b7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da20d9f2ad414b6bfc45df4fc34c3fc042e1740d759013b54b408f28740fef3f"
    hash2       = "307c62eb5d0e72645486ed8ab490a017889f28cb40d74f607fae031e9ef250fb"

  strings:
    $s1 = ",(function f000(){return \"KXg\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Oh\";})(),(function f000(){" ascii
    $s2 = " \"Sj\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"OUx\";})(),(func" ascii
    $s3 = "f000(){return \"MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"TK" ascii
    $s4 = "0(){return \"Sj\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";" ascii
    $s5 = "n \"DNa\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}