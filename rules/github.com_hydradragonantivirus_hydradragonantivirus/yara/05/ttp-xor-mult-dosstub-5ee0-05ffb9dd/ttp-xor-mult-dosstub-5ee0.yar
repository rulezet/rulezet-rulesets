rule TTP_XOR_MULT_DOSStub_5ee0 {
  strings:
    $key_5ee0 = { 0a 88 [2] 7e 90 [2] 39 92 [2] 7e 83 [2] 30 8f [2] 3c 85 [2] 2b 8e [2] 30 c0 [2] 0d }

  condition:
    any of them
}