rule TTP_XOR_MULT_DOSStub_0267 {
  strings:
    $key_0267 = { 56 0f [2] 22 17 [2] 65 15 [2] 22 04 [2] 6c 08 [2] 60 02 [2] 77 09 [2] 6c 47 [2] 51 }

  condition:
    any of them
}