rule TTP_XOR_MULT_DOSStub_3ce0 {
  strings:
    $key_3ce0 = { 68 88 [2] 1c 90 [2] 5b 92 [2] 1c 83 [2] 52 8f [2] 5e 85 [2] 49 8e [2] 52 c0 [2] 6f }

  condition:
    any of them
}