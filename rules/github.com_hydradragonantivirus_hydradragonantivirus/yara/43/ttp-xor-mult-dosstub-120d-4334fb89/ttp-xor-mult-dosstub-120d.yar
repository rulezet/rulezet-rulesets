rule TTP_XOR_MULT_DOSStub_120d {
  strings:
    $key_120d = { 46 65 [2] 32 7d [2] 75 7f [2] 32 6e [2] 7c 62 [2] 70 68 [2] 67 63 [2] 7c 2d [2] 41 }

  condition:
    any of them
}