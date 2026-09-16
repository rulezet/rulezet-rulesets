rule TTP_XOR_MULT_DOSStub_6b26 {
  strings:
    $key_6b26 = { 3f 4e [2] 4b 56 [2] 0c 54 [2] 4b 45 [2] 05 49 [2] 09 43 [2] 1e 48 [2] 05 06 [2] 38 }

  condition:
    any of them
}