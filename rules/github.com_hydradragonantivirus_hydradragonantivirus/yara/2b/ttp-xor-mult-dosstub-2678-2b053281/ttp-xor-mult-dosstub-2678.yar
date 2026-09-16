rule TTP_XOR_MULT_DOSStub_2678 {
  strings:
    $key_2678 = { 72 10 [2] 06 08 [2] 41 0a [2] 06 1b [2] 48 17 [2] 44 1d [2] 53 16 [2] 48 58 [2] 75 }

  condition:
    any of them
}