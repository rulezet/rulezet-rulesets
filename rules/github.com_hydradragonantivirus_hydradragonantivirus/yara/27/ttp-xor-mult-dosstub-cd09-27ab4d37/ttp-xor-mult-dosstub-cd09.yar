rule TTP_XOR_MULT_DOSStub_cd09 {
  strings:
    $key_cd09 = { 99 61 [2] ed 79 [2] aa 7b [2] ed 6a [2] a3 66 [2] af 6c [2] b8 67 [2] a3 29 [2] 9e }

  condition:
    any of them
}