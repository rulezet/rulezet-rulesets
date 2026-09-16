rule TTP_XOR_MULT_DOSStub_081d {
  strings:
    $key_081d = { 5c 75 [2] 28 6d [2] 6f 6f [2] 28 7e [2] 66 72 [2] 6a 78 [2] 7d 73 [2] 66 3d [2] 5b }

  condition:
    any of them
}