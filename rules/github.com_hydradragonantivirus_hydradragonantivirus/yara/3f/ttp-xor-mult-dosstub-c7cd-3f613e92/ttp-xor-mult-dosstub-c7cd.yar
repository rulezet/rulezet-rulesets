rule TTP_XOR_MULT_DOSStub_c7cd {
  strings:
    $key_c7cd = { 93 a5 [2] e7 bd [2] a0 bf [2] e7 ae [2] a9 a2 [2] a5 a8 [2] b2 a3 [2] a9 ed [2] 94 }

  condition:
    any of them
}