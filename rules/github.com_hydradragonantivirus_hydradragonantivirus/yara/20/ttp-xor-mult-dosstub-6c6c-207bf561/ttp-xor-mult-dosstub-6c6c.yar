rule TTP_XOR_MULT_DOSStub_6c6c {
  strings:
    $key_6c6c = { 38 04 [2] 4c 1c [2] 0b 1e [2] 4c 0f [2] 02 03 [2] 0e 09 [2] 19 02 [2] 02 4c [2] 3f }

  condition:
    any of them
}