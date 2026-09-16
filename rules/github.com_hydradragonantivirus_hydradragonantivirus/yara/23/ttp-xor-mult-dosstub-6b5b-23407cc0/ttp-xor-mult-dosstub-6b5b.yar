rule TTP_XOR_MULT_DOSStub_6b5b {
  strings:
    $key_6b5b = { 3f 33 [2] 4b 2b [2] 0c 29 [2] 4b 38 [2] 05 34 [2] 09 3e [2] 1e 35 [2] 05 7b [2] 38 }

  condition:
    any of them
}