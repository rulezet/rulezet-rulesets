rule TTP_XOR_MULT_DOSStub_356c {
  strings:
    $key_356c = { 61 04 [2] 15 1c [2] 52 1e [2] 15 0f [2] 5b 03 [2] 57 09 [2] 40 02 [2] 5b 4c [2] 66 }

  condition:
    any of them
}