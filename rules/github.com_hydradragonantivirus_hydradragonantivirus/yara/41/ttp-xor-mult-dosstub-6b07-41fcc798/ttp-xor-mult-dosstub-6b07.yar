rule TTP_XOR_MULT_DOSStub_6b07 {
  strings:
    $key_6b07 = { 3f 6f [2] 4b 77 [2] 0c 75 [2] 4b 64 [2] 05 68 [2] 09 62 [2] 1e 69 [2] 05 27 [2] 38 }

  condition:
    any of them
}