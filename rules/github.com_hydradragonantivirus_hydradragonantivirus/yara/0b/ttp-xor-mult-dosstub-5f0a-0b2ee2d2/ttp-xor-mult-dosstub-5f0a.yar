rule TTP_XOR_MULT_DOSStub_5f0a {
  strings:
    $key_5f0a = { 0b 62 [2] 7f 7a [2] 38 78 [2] 7f 69 [2] 31 65 [2] 3d 6f [2] 2a 64 [2] 31 2a [2] 0c }

  condition:
    any of them
}