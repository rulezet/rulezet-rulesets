rule TTP_XOR_MULT_DOSStub_466c {
  strings:
    $key_466c = { 12 04 [2] 66 1c [2] 21 1e [2] 66 0f [2] 28 03 [2] 24 09 [2] 33 02 [2] 28 4c [2] 15 }

  condition:
    any of them
}