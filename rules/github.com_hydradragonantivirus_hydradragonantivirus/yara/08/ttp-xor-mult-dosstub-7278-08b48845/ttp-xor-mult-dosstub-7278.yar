rule TTP_XOR_MULT_DOSStub_7278 {
  strings:
    $key_7278 = { 26 10 [2] 52 08 [2] 15 0a [2] 52 1b [2] 1c 17 [2] 10 1d [2] 07 16 [2] 1c 58 [2] 21 }

  condition:
    any of them
}