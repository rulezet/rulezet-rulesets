rule TTP_XOR_MULT_DOSStub_076c {
  strings:
    $key_076c = { 53 04 [2] 27 1c [2] 60 1e [2] 27 0f [2] 69 03 [2] 65 09 [2] 72 02 [2] 69 4c [2] 54 }

  condition:
    any of them
}