rule TTP_XOR_MULT_DOSStub_651d {
  strings:
    $key_651d = { 31 75 [2] 45 6d [2] 02 6f [2] 45 7e [2] 0b 72 [2] 07 78 [2] 10 73 [2] 0b 3d [2] 36 }

  condition:
    any of them
}