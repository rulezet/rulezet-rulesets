rule TTP_XOR_MULT_DOSStub_0ee0 {
  strings:
    $key_0ee0 = { 5a 88 [2] 2e 90 [2] 69 92 [2] 2e 83 [2] 60 8f [2] 6c 85 [2] 7b 8e [2] 60 c0 [2] 5d }

  condition:
    any of them
}