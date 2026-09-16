rule TTP_XOR_MULT_DOSStub_e33a {
  strings:
    $key_e33a = { b7 52 [2] c3 4a [2] 84 48 [2] c3 59 [2] 8d 55 [2] 81 5f [2] 96 54 [2] 8d 1a [2] b0 }

  condition:
    any of them
}