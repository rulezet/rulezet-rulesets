rule TTP_XOR_MULT_DOSStub_cd5f {
  strings:
    $key_cd5f = { 99 37 [2] ed 2f [2] aa 2d [2] ed 3c [2] a3 30 [2] af 3a [2] b8 31 [2] a3 7f [2] 9e }

  condition:
    any of them
}