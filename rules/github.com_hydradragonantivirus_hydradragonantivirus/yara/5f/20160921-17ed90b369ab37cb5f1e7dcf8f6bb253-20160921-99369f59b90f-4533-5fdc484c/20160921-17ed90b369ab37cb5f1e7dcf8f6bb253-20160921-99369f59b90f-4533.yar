rule _20160921_17ed90b369ab37cb5f1e7dcf8f6bb253_20160921_99369f59b90f_4533 {
  meta:
    description = "datamaliciousorder - from files 20160921_17ed90b369ab37cb5f1e7dcf8f6bb253.js, 20160921_99369f59b90fb2df18b8570f0403febc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81de0ae14e0c288b697a0e3c7f3ced9b68b8377e75dff5322d654841e642a8a7"
    hash2       = "224e0a3dfee910c8afb81d7298f89c0b6e937cbd8062c03cedbe500c3dfe98a2"

  strings:
    $s1 = "eturn \"Nx\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Qa\";})()," ascii
    $s2 = "tion f000(){return \"Go\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return" ascii
    $s3 = "eturn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"ZFe\";})()," ascii
    $s4 = "{return \"BQb\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"PTi\";})" ascii
    $s5 = "0(){return \"Kw\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"XTn\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}