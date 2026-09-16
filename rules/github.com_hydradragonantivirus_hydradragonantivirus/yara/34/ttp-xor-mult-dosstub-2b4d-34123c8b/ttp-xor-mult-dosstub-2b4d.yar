rule TTP_XOR_MULT_DOSStub_2b4d {
  strings:
    $key_2b4d = { 7f 25 [2] 0b 3d [2] 4c 3f [2] 0b 2e [2] 45 22 [2] 49 28 [2] 5e 23 [2] 45 6d [2] 78 }

  condition:
    any of them
}