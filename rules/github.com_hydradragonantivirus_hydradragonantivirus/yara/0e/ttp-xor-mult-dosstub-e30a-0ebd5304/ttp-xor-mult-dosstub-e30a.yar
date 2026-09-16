rule TTP_XOR_MULT_DOSStub_e30a {
  strings:
    $key_e30a = { b7 62 [2] c3 7a [2] 84 78 [2] c3 69 [2] 8d 65 [2] 81 6f [2] 96 64 [2] 8d 2a [2] b0 }

  condition:
    any of them
}