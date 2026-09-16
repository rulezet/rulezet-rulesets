rule TTP_XOR_MULT_DOSStub_390a {
  strings:
    $key_390a = { 6d 62 [2] 19 7a [2] 5e 78 [2] 19 69 [2] 57 65 [2] 5b 6f [2] 4c 64 [2] 57 2a [2] 6a }

  condition:
    any of them
}