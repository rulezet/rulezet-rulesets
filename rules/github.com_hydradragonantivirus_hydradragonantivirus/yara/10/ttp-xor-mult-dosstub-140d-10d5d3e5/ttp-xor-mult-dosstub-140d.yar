rule TTP_XOR_MULT_DOSStub_140d {
  strings:
    $key_140d = { 40 65 [2] 34 7d [2] 73 7f [2] 34 6e [2] 7a 62 [2] 76 68 [2] 61 63 [2] 7a 2d [2] 47 }

  condition:
    any of them
}