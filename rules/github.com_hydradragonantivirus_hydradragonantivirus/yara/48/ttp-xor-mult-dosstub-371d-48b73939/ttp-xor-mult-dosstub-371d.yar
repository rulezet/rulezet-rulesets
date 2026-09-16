rule TTP_XOR_MULT_DOSStub_371d {
  strings:
    $key_371d = { 63 75 [2] 17 6d [2] 50 6f [2] 17 7e [2] 59 72 [2] 55 78 [2] 42 73 [2] 59 3d [2] 64 }

  condition:
    any of them
}