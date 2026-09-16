rule TTP_XOR_MULT_DOSStub_e111 {
  strings:
    $key_e111 = { b5 79 [2] c1 61 [2] 86 63 [2] c1 72 [2] 8f 7e [2] 83 74 [2] 94 7f [2] 8f 31 [2] b2 }

  condition:
    any of them
}