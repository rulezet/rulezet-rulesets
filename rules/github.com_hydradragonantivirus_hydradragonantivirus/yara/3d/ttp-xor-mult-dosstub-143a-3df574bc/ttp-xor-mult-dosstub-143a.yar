rule TTP_XOR_MULT_DOSStub_143a {
  strings:
    $key_143a = { 40 52 [2] 34 4a [2] 73 48 [2] 34 59 [2] 7a 55 [2] 76 5f [2] 61 54 [2] 7a 1a [2] 47 }

  condition:
    any of them
}