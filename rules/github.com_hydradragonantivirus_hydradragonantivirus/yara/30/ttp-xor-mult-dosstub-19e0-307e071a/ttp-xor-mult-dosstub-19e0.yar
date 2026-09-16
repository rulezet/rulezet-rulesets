rule TTP_XOR_MULT_DOSStub_19e0 {
  strings:
    $key_19e0 = { 4d 88 [2] 39 90 [2] 7e 92 [2] 39 83 [2] 77 8f [2] 7b 85 [2] 6c 8e [2] 77 c0 [2] 4a }

  condition:
    any of them
}