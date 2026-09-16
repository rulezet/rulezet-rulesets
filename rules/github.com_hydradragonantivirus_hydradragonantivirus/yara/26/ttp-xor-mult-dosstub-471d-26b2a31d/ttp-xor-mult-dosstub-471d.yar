rule TTP_XOR_MULT_DOSStub_471d {
  strings:
    $key_471d = { 13 75 [2] 67 6d [2] 20 6f [2] 67 7e [2] 29 72 [2] 25 78 [2] 32 73 [2] 29 3d [2] 14 }

  condition:
    any of them
}