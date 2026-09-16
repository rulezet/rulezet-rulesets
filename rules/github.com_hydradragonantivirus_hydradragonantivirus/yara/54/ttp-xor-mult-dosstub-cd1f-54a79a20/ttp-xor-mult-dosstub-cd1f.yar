rule TTP_XOR_MULT_DOSStub_cd1f {
  strings:
    $key_cd1f = { 99 77 [2] ed 6f [2] aa 6d [2] ed 7c [2] a3 70 [2] af 7a [2] b8 71 [2] a3 3f [2] 9e }

  condition:
    any of them
}