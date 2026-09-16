rule _20160921_cb6c4de61b30cd204129d0942321058c_20160921_fff847efa0ea_3144 {
  meta:
    description = "datamaliciousorder - from files 20160921_cb6c4de61b30cd204129d0942321058c.js, 20160921_fff847efa0eaa326a0aad4d2fc81d41e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db98233c2508e4a2167ee46a334ce9052faa726615e89838f4fdb36b74fc5353"
    hash2       = "93f868a10878cb41f305e28c8802778903c99b84a1bc0647a0c2c78fd6310577"

  strings:
    $s1 = "(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Vu\";}" ascii
    $s2 = "rn \"OUx\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Tn\";})(),(fu" ascii
    $s3 = "ction f000(){return \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Lo\";})(),(function f000(){retur" ascii
    $s4 = "tion f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"KDh\";})(),(function f000(){retur" ascii
    $s5 = "return \"MMz\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TRc\";})(" ascii
    $s6 = "BMj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Sv\";})(),(functio" ascii
    $s7 = "ion f000(){return \"QDg\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"PTs\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}