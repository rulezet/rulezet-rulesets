rule TTP_XOR_MULT_DOSStub_173a {
  strings:
    $key_173a = { 43 52 [2] 37 4a [2] 70 48 [2] 37 59 [2] 79 55 [2] 75 5f [2] 62 54 [2] 79 1a [2] 44 }

  condition:
    any of them
}