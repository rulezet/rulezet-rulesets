rule TTP_XOR_MULT_DOSStub_3648 {
  strings:
    $key_3648 = { 62 20 [2] 16 38 [2] 51 3a [2] 16 2b [2] 58 27 [2] 54 2d [2] 43 26 [2] 58 68 [2] 65 }

  condition:
    any of them
}