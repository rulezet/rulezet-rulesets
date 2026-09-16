rule TTP_XOR_MULT_DOSStub_6b4c {
  strings:
    $key_6b4c = { 3f 24 [2] 4b 3c [2] 0c 3e [2] 4b 2f [2] 05 23 [2] 09 29 [2] 1e 22 [2] 05 6c [2] 38 }

  condition:
    any of them
}