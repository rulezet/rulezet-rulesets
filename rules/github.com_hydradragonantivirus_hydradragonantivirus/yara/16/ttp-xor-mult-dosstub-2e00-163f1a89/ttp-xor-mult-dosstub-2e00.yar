rule TTP_XOR_MULT_DOSStub_2e00 {
  strings:
    $key_2e00 = { 7a 68 [2] 0e 70 [2] 49 72 [2] 0e 63 [2] 40 6f [2] 4c 65 [2] 5b 6e [2] 40 20 [2] 7d }

  condition:
    any of them
}