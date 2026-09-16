rule TTP_XOR_MULT_DOSStub_1e00 {
  strings:
    $key_1e00 = { 4a 68 [2] 3e 70 [2] 79 72 [2] 3e 63 [2] 70 6f [2] 7c 65 [2] 6b 6e [2] 70 20 [2] 4d }

  condition:
    any of them
}