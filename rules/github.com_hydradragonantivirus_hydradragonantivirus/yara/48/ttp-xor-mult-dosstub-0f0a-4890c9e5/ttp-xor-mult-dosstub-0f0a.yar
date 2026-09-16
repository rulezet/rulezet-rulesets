rule TTP_XOR_MULT_DOSStub_0f0a {
  strings:
    $key_0f0a = { 5b 62 [2] 2f 7a [2] 68 78 [2] 2f 69 [2] 61 65 [2] 6d 6f [2] 7a 64 [2] 61 2a [2] 5c }

  condition:
    any of them
}