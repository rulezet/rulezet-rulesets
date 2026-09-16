rule TTP_XOR_MULT_DOSStub_cde9 {
  strings:
    $key_cde9 = { 99 81 [2] ed 99 [2] aa 9b [2] ed 8a [2] a3 86 [2] af 8c [2] b8 87 [2] a3 c9 [2] 9e }

  condition:
    any of them
}