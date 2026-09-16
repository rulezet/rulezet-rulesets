rule TTP_XOR_MULT_DOSStub_021b {
  strings:
    $key_021b = { 56 73 [2] 22 6b [2] 65 69 [2] 22 78 [2] 6c 74 [2] 60 7e [2] 77 75 [2] 6c 3b [2] 51 }

  condition:
    any of them
}