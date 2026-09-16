rule TTP_XOR_MULT_DOSStub_532c {
  strings:
    $key_532c = { 07 44 [2] 73 5c [2] 34 5e [2] 73 4f [2] 3d 43 [2] 31 49 [2] 26 42 [2] 3d 0c [2] 00 }

  condition:
    any of them
}