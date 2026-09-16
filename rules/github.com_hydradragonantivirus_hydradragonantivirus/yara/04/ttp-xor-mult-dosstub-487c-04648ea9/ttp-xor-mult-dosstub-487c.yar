rule TTP_XOR_MULT_DOSStub_487c {
  strings:
    $key_487c = { 1c 14 [2] 68 0c [2] 2f 0e [2] 68 1f [2] 26 13 [2] 2a 19 [2] 3d 12 [2] 26 5c [2] 1b }

  condition:
    any of them
}