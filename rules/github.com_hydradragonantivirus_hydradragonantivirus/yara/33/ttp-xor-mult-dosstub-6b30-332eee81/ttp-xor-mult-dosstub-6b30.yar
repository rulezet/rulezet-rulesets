rule TTP_XOR_MULT_DOSStub_6b30 {
  strings:
    $key_6b30 = { 3f 58 [2] 4b 40 [2] 0c 42 [2] 4b 53 [2] 05 5f [2] 09 55 [2] 1e 5e [2] 05 10 [2] 38 }

  condition:
    any of them
}