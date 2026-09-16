rule TTP_XOR_MULT_DOSStub_282c {
  strings:
    $key_282c = { 7c 44 [2] 08 5c [2] 4f 5e [2] 08 4f [2] 46 43 [2] 4a 49 [2] 5d 42 [2] 46 0c [2] 7b }

  condition:
    any of them
}