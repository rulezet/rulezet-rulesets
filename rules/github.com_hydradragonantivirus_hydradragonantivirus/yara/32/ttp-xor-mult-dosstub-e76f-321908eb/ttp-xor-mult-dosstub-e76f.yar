rule TTP_XOR_MULT_DOSStub_e76f {
  strings:
    $key_e76f = { b3 07 [2] c7 1f [2] 80 1d [2] c7 0c [2] 89 00 [2] 85 0a [2] 92 01 [2] 89 4f [2] b4 }

  condition:
    any of them
}