rule TTP_XOR_MULT_DOSStub_3a6c {
  strings:
    $key_3a6c = { 6e 04 [2] 1a 1c [2] 5d 1e [2] 1a 0f [2] 54 03 [2] 58 09 [2] 4f 02 [2] 54 4c [2] 69 }

  condition:
    any of them
}