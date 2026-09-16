rule TTP_XOR_MULT_DOSStub_19e6 {
  strings:
    $key_19e6 = { 4d 8e [2] 39 96 [2] 7e 94 [2] 39 85 [2] 77 89 [2] 7b 83 [2] 6c 88 [2] 77 c6 [2] 4a }

  condition:
    any of them
}