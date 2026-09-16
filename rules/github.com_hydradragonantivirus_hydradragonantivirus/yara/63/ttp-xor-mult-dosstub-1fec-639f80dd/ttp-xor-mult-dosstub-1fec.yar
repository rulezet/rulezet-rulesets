rule TTP_XOR_MULT_DOSStub_1fec {
  strings:
    $key_1fec = { 4b 84 [2] 3f 9c [2] 78 9e [2] 3f 8f [2] 71 83 [2] 7d 89 [2] 6a 82 [2] 71 cc [2] 4c }

  condition:
    any of them
}