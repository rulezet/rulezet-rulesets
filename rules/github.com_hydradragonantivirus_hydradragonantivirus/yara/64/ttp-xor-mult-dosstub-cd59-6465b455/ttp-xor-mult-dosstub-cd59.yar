rule TTP_XOR_MULT_DOSStub_cd59 {
  strings:
    $key_cd59 = { 99 31 [2] ed 29 [2] aa 2b [2] ed 3a [2] a3 36 [2] af 3c [2] b8 37 [2] a3 79 [2] 9e }

  condition:
    any of them
}