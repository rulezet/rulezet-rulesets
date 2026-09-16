rule TTP_XOR_MULT_DOSStub_616c {
  strings:
    $key_616c = { 35 04 [2] 41 1c [2] 06 1e [2] 41 0f [2] 0f 03 [2] 03 09 [2] 14 02 [2] 0f 4c [2] 32 }

  condition:
    any of them
}