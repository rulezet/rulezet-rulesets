rule TTP_XOR_MULT_DOSStub_793a {
  strings:
    $key_793a = { 2d 52 [2] 59 4a [2] 1e 48 [2] 59 59 [2] 17 55 [2] 1b 5f [2] 0c 54 [2] 17 1a [2] 2a }

  condition:
    any of them
}