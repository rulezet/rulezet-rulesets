rule TTP_XOR_MULT_DOSStub_3e50 {
  strings:
    $key_3e50 = { 6a 38 [2] 1e 20 [2] 59 22 [2] 1e 33 [2] 50 3f [2] 5c 35 [2] 4b 3e [2] 50 70 [2] 6d }

  condition:
    any of them
}