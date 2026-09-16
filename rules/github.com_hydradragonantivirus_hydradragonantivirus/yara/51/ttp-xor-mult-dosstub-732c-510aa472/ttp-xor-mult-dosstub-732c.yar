rule TTP_XOR_MULT_DOSStub_732c {
  strings:
    $key_732c = { 27 44 [2] 53 5c [2] 14 5e [2] 53 4f [2] 1d 43 [2] 11 49 [2] 06 42 [2] 1d 0c [2] 20 }

  condition:
    any of them
}