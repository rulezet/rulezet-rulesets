rule TTP_XOR_MULT_DOSStub_461d {
  strings:
    $key_461d = { 12 75 [2] 66 6d [2] 21 6f [2] 66 7e [2] 28 72 [2] 24 78 [2] 33 73 [2] 28 3d [2] 15 }

  condition:
    any of them
}