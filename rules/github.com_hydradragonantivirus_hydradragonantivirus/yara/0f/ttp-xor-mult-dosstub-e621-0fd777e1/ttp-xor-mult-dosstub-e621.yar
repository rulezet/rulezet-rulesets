rule TTP_XOR_MULT_DOSStub_e621 {
  strings:
    $key_e621 = { b2 49 [2] c6 51 [2] 81 53 [2] c6 42 [2] 88 4e [2] 84 44 [2] 93 4f [2] 88 01 [2] b5 }

  condition:
    any of them
}