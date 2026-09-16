rule TTP_XOR_MULT_DOSStub_4ce1 {
  strings:
    $key_4ce1 = { 18 89 [2] 6c 91 [2] 2b 93 [2] 6c 82 [2] 22 8e [2] 2e 84 [2] 39 8f [2] 22 c1 [2] 1f }

  condition:
    any of them
}