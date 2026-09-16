rule TTP_XOR_MULT_DOSStub_6d0a {
  strings:
    $key_6d0a = { 39 62 [2] 4d 7a [2] 0a 78 [2] 4d 69 [2] 03 65 [2] 0f 6f [2] 18 64 [2] 03 2a [2] 3e }

  condition:
    any of them
}