rule TTP_XOR_MULT_DOSStub_cd12 {
  strings:
    $key_cd12 = { 99 7a [2] ed 62 [2] aa 60 [2] ed 71 [2] a3 7d [2] af 77 [2] b8 7c [2] a3 32 [2] 9e }

  condition:
    any of them
}