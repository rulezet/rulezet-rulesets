rule TTP_XOR_MULT_DOSStub_cd23 {
  strings:
    $key_cd23 = { 99 4b [2] ed 53 [2] aa 51 [2] ed 40 [2] a3 4c [2] af 46 [2] b8 4d [2] a3 03 [2] 9e }

  condition:
    any of them
}