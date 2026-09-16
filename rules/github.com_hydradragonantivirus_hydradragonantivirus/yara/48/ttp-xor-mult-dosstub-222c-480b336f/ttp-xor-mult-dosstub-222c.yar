rule TTP_XOR_MULT_DOSStub_222c {
  strings:
    $key_222c = { 76 44 [2] 02 5c [2] 45 5e [2] 02 4f [2] 4c 43 [2] 40 49 [2] 57 42 [2] 4c 0c [2] 71 }

  condition:
    any of them
}