rule TTP_XOR_MULT_DOSStub_6eec {
  strings:
    $key_6eec = { 3a 84 [2] 4e 9c [2] 09 9e [2] 4e 8f [2] 00 83 [2] 0c 89 [2] 1b 82 [2] 00 cc [2] 3d }

  condition:
    any of them
}