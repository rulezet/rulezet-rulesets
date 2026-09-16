rule TTP_XOR_MULT_DOSStub_412c {
  strings:
    $key_412c = { 15 44 [2] 61 5c [2] 26 5e [2] 61 4f [2] 2f 43 [2] 23 49 [2] 34 42 [2] 2f 0c [2] 12 }

  condition:
    any of them
}