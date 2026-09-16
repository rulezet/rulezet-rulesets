rule TTP_XOR_MULT_DOSStub_0ef0 {
  strings:
    $key_0ef0 = { 5a 98 [2] 2e 80 [2] 69 82 [2] 2e 93 [2] 60 9f [2] 6c 95 [2] 7b 9e [2] 60 d0 [2] 5d }

  condition:
    any of them
}