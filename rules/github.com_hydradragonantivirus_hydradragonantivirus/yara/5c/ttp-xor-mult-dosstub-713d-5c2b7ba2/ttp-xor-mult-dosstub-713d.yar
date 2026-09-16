rule TTP_XOR_MULT_DOSStub_713d {
  strings:
    $key_713d = { 25 55 [2] 51 4d [2] 16 4f [2] 51 5e [2] 1f 52 [2] 13 58 [2] 04 53 [2] 1f 1d [2] 22 }

  condition:
    any of them
}