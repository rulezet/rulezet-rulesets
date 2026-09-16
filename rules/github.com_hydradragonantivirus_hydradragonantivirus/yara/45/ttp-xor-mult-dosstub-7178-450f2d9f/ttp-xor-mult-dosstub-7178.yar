rule TTP_XOR_MULT_DOSStub_7178 {
  strings:
    $key_7178 = { 25 10 [2] 51 08 [2] 16 0a [2] 51 1b [2] 1f 17 [2] 13 1d [2] 04 16 [2] 1f 58 [2] 22 }

  condition:
    any of them
}