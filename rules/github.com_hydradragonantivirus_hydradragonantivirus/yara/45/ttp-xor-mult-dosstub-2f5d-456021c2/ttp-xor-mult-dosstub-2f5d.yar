rule TTP_XOR_MULT_DOSStub_2f5d {
  strings:
    $key_2f5d = { 7b 35 [2] 0f 2d [2] 48 2f [2] 0f 3e [2] 41 32 [2] 4d 38 [2] 5a 33 [2] 41 7d [2] 7c }

  condition:
    any of them
}