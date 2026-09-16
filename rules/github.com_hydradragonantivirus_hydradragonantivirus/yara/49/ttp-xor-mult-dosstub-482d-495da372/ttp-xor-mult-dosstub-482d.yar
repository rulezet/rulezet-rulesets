rule TTP_XOR_MULT_DOSStub_482d {
  strings:
    $key_482d = { 1c 45 [2] 68 5d [2] 2f 5f [2] 68 4e [2] 26 42 [2] 2a 48 [2] 3d 43 [2] 26 0d [2] 1b }

  condition:
    any of them
}