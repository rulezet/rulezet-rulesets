rule TTP_XOR_MULT_DOSStub_615d {
  strings:
    $key_615d = { 35 35 [2] 41 2d [2] 06 2f [2] 41 3e [2] 0f 32 [2] 03 38 [2] 14 33 [2] 0f 7d [2] 32 }

  condition:
    any of them
}