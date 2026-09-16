rule TTP_XOR_MULT_DOSStub_e32a {
  strings:
    $key_e32a = { b7 42 [2] c3 5a [2] 84 58 [2] c3 49 [2] 8d 45 [2] 81 4f [2] 96 44 [2] 8d 0a [2] b0 }

  condition:
    any of them
}