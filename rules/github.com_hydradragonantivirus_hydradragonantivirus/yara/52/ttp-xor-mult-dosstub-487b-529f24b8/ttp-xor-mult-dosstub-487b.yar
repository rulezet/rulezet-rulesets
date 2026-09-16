rule TTP_XOR_MULT_DOSStub_487b {
  strings:
    $key_487b = { 1c 13 [2] 68 0b [2] 2f 09 [2] 68 18 [2] 26 14 [2] 2a 1e [2] 3d 15 [2] 26 5b [2] 1b }

  condition:
    any of them
}