rule TTP_XOR_MULT_DOSStub_226e {
  strings:
    $key_226e = { 76 06 [2] 02 1e [2] 45 1c [2] 02 0d [2] 4c 01 [2] 40 0b [2] 57 00 [2] 4c 4e [2] 71 }

  condition:
    any of them
}