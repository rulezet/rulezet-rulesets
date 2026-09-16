rule TTP_XOR_MULT_DOSStub_145d {
  strings:
    $key_145d = { 40 35 [2] 34 2d [2] 73 2f [2] 34 3e [2] 7a 32 [2] 76 38 [2] 61 33 [2] 7a 7d [2] 47 }

  condition:
    any of them
}