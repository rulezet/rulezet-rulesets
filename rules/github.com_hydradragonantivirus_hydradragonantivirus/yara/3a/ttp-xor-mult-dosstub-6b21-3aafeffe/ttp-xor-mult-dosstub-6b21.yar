rule TTP_XOR_MULT_DOSStub_6b21 {
  strings:
    $key_6b21 = { 3f 49 [2] 4b 51 [2] 0c 53 [2] 4b 42 [2] 05 4e [2] 09 44 [2] 1e 4f [2] 05 01 [2] 38 }

  condition:
    any of them
}