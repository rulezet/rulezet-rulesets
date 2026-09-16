rule TTP_XOR_MULT_DOSStub_000a {
  strings:
    $key_000a = { 54 62 [2] 20 7a [2] 67 78 [2] 20 69 [2] 6e 65 [2] 62 6f [2] 75 64 [2] 6e 2a [2] 53 }

  condition:
    any of them
}