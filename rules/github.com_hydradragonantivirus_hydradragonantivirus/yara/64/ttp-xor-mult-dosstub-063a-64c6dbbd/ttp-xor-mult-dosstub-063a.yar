rule TTP_XOR_MULT_DOSStub_063a {
  strings:
    $key_063a = { 52 52 [2] 26 4a [2] 61 48 [2] 26 59 [2] 68 55 [2] 64 5f [2] 73 54 [2] 68 1a [2] 55 }

  condition:
    any of them
}