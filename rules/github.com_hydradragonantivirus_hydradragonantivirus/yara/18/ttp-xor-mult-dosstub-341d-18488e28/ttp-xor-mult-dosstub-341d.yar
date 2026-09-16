rule TTP_XOR_MULT_DOSStub_341d {
  strings:
    $key_341d = { 60 75 [2] 14 6d [2] 53 6f [2] 14 7e [2] 5a 72 [2] 56 78 [2] 41 73 [2] 5a 3d [2] 67 }

  condition:
    any of them
}