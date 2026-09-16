rule TTP_XOR_MULT_DOSStub_5e00 {
  strings:
    $key_5e00 = { 0a 68 [2] 7e 70 [2] 39 72 [2] 7e 63 [2] 30 6f [2] 3c 65 [2] 2b 6e [2] 30 20 [2] 0d }

  condition:
    any of them
}