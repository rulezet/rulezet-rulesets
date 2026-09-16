rule TTP_XOR_MULT_DOSStub_776c {
  strings:
    $key_776c = { 23 04 [2] 57 1c [2] 10 1e [2] 57 0f [2] 19 03 [2] 15 09 [2] 02 02 [2] 19 4c [2] 24 }

  condition:
    any of them
}