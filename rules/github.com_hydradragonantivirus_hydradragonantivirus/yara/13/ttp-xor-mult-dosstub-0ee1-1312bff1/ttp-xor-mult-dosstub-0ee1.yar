rule TTP_XOR_MULT_DOSStub_0ee1 {
  strings:
    $key_0ee1 = { 5a 89 [2] 2e 91 [2] 69 93 [2] 2e 82 [2] 60 8e [2] 6c 84 [2] 7b 8f [2] 60 c1 [2] 5d }

  condition:
    any of them
}