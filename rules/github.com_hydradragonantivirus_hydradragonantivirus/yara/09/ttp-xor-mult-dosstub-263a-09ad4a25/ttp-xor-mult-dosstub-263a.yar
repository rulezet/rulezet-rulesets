rule TTP_XOR_MULT_DOSStub_263a {
  strings:
    $key_263a = { 72 52 [2] 06 4a [2] 41 48 [2] 06 59 [2] 48 55 [2] 44 5f [2] 53 54 [2] 48 1a [2] 75 }

  condition:
    any of them
}