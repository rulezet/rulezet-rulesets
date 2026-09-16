rule TTP_XOR_MULT_DOSStub_1926 {
  strings:
    $key_1926 = { 4d 4e [2] 39 56 [2] 7e 54 [2] 39 45 [2] 77 49 [2] 7b 43 [2] 6c 48 [2] 77 06 [2] 4a }

  condition:
    any of them
}