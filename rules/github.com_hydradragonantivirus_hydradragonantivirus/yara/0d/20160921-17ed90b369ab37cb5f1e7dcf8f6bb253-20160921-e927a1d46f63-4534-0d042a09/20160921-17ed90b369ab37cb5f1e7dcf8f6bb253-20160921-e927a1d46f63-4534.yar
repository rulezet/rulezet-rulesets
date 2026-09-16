rule _20160921_17ed90b369ab37cb5f1e7dcf8f6bb253_20160921_e927a1d46f63_4534 {
  meta:
    description = "datamaliciousorder - from files 20160921_17ed90b369ab37cb5f1e7dcf8f6bb253.js, 20160921_e927a1d46f63fcc6ccb740b1d71293f3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81de0ae14e0c288b697a0e3c7f3ced9b68b8377e75dff5322d654841e642a8a7"
    hash2       = "a681cf04685052da0d288a0246e49880f34a91dc46ff378f7cf1859ae526c1ef"

  strings:
    $s1 = "n \"Yv\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"MDb\";})(),(fun" ascii
    $s2 = "){return \"KDh\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";" ascii
    $s3 = "(),(function f000(){return \"Go\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"MDb\";})(),(function f000()" ascii
    $s4 = "function f000(){return \"Nv\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Nx\";})(),(function f000(){ret" ascii
    $s5 = "00(){return \"Qa\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"MDb" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}