rule TTP_XOR_MULT_DOSStub_5aec {
  strings:
    $key_5aec = { 0e 84 [2] 7a 9c [2] 3d 9e [2] 7a 8f [2] 34 83 [2] 38 89 [2] 2f 82 [2] 34 cc [2] 09 }

  condition:
    any of them
}