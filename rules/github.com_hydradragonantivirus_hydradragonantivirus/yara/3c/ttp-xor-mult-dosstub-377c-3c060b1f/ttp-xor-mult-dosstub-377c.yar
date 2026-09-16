rule TTP_XOR_MULT_DOSStub_377c {
  strings:
    $key_377c = { 63 14 [2] 17 0c [2] 50 0e [2] 17 1f [2] 59 13 [2] 55 19 [2] 42 12 [2] 59 5c [2] 64 }

  condition:
    any of them
}