rule TTP_XOR_MULT_DOSStub_e32f {
  strings:
    $key_e32f = { b7 47 [2] c3 5f [2] 84 5d [2] c3 4c [2] 8d 40 [2] 81 4a [2] 96 41 [2] 8d 0f [2] b0 }

  condition:
    any of them
}