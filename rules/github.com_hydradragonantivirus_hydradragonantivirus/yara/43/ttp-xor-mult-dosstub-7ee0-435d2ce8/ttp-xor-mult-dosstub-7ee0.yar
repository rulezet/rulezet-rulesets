rule TTP_XOR_MULT_DOSStub_7ee0 {
  strings:
    $key_7ee0 = { 2a 88 [2] 5e 90 [2] 19 92 [2] 5e 83 [2] 10 8f [2] 1c 85 [2] 0b 8e [2] 10 c0 [2] 2d }

  condition:
    any of them
}