rule TTP_XOR_MULT_DOSStub_2f0a {
  strings:
    $key_2f0a = { 7b 62 [2] 0f 7a [2] 48 78 [2] 0f 69 [2] 41 65 [2] 4d 6f [2] 5a 64 [2] 41 2a [2] 7c }

  condition:
    any of them
}