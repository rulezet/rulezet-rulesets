rule TTP_XOR_MULT_DOSStub_0a0a {
  strings:
    $key_0a0a = { 5e 62 [2] 2a 7a [2] 6d 78 [2] 2a 69 [2] 64 65 [2] 68 6f [2] 7f 64 [2] 64 2a [2] 59 }

  condition:
    any of them
}