rule TTP_XOR_MULT_DOSStub_165d {
  strings:
    $key_165d = { 42 35 [2] 36 2d [2] 71 2f [2] 36 3e [2] 78 32 [2] 74 38 [2] 63 33 [2] 78 7d [2] 45 }

  condition:
    any of them
}