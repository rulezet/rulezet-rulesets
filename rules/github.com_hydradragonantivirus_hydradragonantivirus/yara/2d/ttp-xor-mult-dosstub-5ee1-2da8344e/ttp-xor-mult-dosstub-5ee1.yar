rule TTP_XOR_MULT_DOSStub_5ee1 {
  strings:
    $key_5ee1 = { 0a 89 [2] 7e 91 [2] 39 93 [2] 7e 82 [2] 30 8e [2] 3c 84 [2] 2b 8f [2] 30 c1 [2] 0d }

  condition:
    any of them
}