rule TTP_XOR_MULT_DOSStub_7211 {
  strings:
    $key_7211 = { 26 79 [2] 52 61 [2] 15 63 [2] 52 72 [2] 1c 7e [2] 10 74 [2] 07 7f [2] 1c 31 [2] 21 }

  condition:
    any of them
}