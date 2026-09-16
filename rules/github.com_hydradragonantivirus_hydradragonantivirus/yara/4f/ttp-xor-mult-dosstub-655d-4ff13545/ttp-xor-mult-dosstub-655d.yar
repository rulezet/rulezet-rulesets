rule TTP_XOR_MULT_DOSStub_655d {
  strings:
    $key_655d = { 31 35 [2] 45 2d [2] 02 2f [2] 45 3e [2] 0b 32 [2] 07 38 [2] 10 33 [2] 0b 7d [2] 36 }

  condition:
    any of them
}