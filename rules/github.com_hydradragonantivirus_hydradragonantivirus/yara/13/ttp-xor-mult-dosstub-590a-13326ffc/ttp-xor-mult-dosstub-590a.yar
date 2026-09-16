rule TTP_XOR_MULT_DOSStub_590a {
  strings:
    $key_590a = { 0d 62 [2] 79 7a [2] 3e 78 [2] 79 69 [2] 37 65 [2] 3b 6f [2] 2c 64 [2] 37 2a [2] 0a }

  condition:
    any of them
}