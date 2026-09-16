rule TTP_XOR_MULT_DOSStub_237d {
  strings:
    $key_237d = { 77 15 [2] 03 0d [2] 44 0f [2] 03 1e [2] 4d 12 [2] 41 18 [2] 56 13 [2] 4d 5d [2] 70 }

  condition:
    any of them
}