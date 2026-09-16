rule TTP_XOR_MULT_DOSStub_752c {
  strings:
    $key_752c = { 21 44 [2] 55 5c [2] 12 5e [2] 55 4f [2] 1b 43 [2] 17 49 [2] 00 42 [2] 1b 0c [2] 26 }

  condition:
    any of them
}