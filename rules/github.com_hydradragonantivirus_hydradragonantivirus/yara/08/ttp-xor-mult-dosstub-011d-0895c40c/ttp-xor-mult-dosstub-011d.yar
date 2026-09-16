rule TTP_XOR_MULT_DOSStub_011d {
  strings:
    $key_011d = { 55 75 [2] 21 6d [2] 66 6f [2] 21 7e [2] 6f 72 [2] 63 78 [2] 74 73 [2] 6f 3d [2] 52 }

  condition:
    any of them
}