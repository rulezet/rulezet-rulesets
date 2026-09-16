rule TTP_XOR_MULT_DOSStub_3678 {
  strings:
    $key_3678 = { 62 10 [2] 16 08 [2] 51 0a [2] 16 1b [2] 58 17 [2] 54 1d [2] 43 16 [2] 58 58 [2] 65 }

  condition:
    any of them
}