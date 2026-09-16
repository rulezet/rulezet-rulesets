rule TTP_XOR_MULT_DOSStub_391d {
  strings:
    $key_391d = { 6d 75 [2] 19 6d [2] 5e 6f [2] 19 7e [2] 57 72 [2] 5b 78 [2] 4c 73 [2] 57 3d [2] 6a }

  condition:
    any of them
}