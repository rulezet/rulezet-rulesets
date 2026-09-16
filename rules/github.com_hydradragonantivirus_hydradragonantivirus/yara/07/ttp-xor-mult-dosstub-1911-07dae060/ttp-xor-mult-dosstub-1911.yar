rule TTP_XOR_MULT_DOSStub_1911 {
  strings:
    $key_1911 = { 4d 79 [2] 39 61 [2] 7e 63 [2] 39 72 [2] 77 7e [2] 7b 74 [2] 6c 7f [2] 77 31 [2] 4a }

  condition:
    any of them
}