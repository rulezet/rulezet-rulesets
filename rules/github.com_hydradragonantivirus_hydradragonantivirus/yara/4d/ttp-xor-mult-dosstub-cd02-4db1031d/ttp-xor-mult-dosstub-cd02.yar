rule TTP_XOR_MULT_DOSStub_cd02 {
  strings:
    $key_cd02 = { 99 6a [2] ed 72 [2] aa 70 [2] ed 61 [2] a3 6d [2] af 67 [2] b8 6c [2] a3 22 [2] 9e }

  condition:
    any of them
}