rule TTP_XOR_MULT_DOSStub_cd13 {
  strings:
    $key_cd13 = { 99 7b [2] ed 63 [2] aa 61 [2] ed 70 [2] a3 7c [2] af 76 [2] b8 7d [2] a3 33 [2] 9e }

  condition:
    any of them
}