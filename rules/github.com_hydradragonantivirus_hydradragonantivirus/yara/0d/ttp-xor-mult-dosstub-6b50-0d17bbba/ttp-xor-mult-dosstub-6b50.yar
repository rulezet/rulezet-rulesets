rule TTP_XOR_MULT_DOSStub_6b50 {
  strings:
    $key_6b50 = { 3f 38 [2] 4b 20 [2] 0c 22 [2] 4b 33 [2] 05 3f [2] 09 35 [2] 1e 3e [2] 05 70 [2] 38 }

  condition:
    any of them
}