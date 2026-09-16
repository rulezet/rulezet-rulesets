rule TTP_XOR_MULT_DOSStub_385d {
  strings:
    $key_385d = { 6c 35 [2] 18 2d [2] 5f 2f [2] 18 3e [2] 56 32 [2] 5a 38 [2] 4d 33 [2] 56 7d [2] 6b }

  condition:
    any of them
}