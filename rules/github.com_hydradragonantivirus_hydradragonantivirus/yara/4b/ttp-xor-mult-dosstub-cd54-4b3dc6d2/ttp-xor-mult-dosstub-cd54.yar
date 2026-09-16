rule TTP_XOR_MULT_DOSStub_cd54 {
  strings:
    $key_cd54 = { 99 3c [2] ed 24 [2] aa 26 [2] ed 37 [2] a3 3b [2] af 31 [2] b8 3a [2] a3 74 [2] 9e }

  condition:
    any of them
}