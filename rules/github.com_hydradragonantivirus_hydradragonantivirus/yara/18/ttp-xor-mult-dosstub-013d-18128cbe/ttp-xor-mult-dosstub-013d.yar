rule TTP_XOR_MULT_DOSStub_013d {
  strings:
    $key_013d = { 55 55 [2] 21 4d [2] 66 4f [2] 21 5e [2] 6f 52 [2] 63 58 [2] 74 53 [2] 6f 1d [2] 52 }

  condition:
    any of them
}