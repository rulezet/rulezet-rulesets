rule TTP_XOR_MULT_DOSStub_cd53 {
  strings:
    $key_cd53 = { 99 3b [2] ed 23 [2] aa 21 [2] ed 30 [2] a3 3c [2] af 36 [2] b8 3d [2] a3 73 [2] 9e }

  condition:
    any of them
}