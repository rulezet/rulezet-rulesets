rule TTP_XOR_MULT_DOSStub_0f0d {
  strings:
    $key_0f0d = { 5b 65 [2] 2f 7d [2] 68 7f [2] 2f 6e [2] 61 62 [2] 6d 68 [2] 7a 63 [2] 61 2d [2] 5c }

  condition:
    any of them
}