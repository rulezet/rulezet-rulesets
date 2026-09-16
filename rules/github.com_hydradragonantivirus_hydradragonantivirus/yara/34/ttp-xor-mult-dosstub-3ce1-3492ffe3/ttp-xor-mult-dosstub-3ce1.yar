rule TTP_XOR_MULT_DOSStub_3ce1 {
  strings:
    $key_3ce1 = { 68 89 [2] 1c 91 [2] 5b 93 [2] 1c 82 [2] 52 8e [2] 5e 84 [2] 49 8f [2] 52 c1 [2] 6f }

  condition:
    any of them
}