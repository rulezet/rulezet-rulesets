rule TTP_XOR_MULT_DOSStub_e36f {
  strings:
    $key_e36f = { b7 07 [2] c3 1f [2] 84 1d [2] c3 0c [2] 8d 00 [2] 81 0a [2] 96 01 [2] 8d 4f [2] b0 }

  condition:
    any of them
}