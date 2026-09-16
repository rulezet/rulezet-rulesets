rule TTP_XOR_MULT_DOSStub_e167 {
  strings:
    $key_e167 = { b5 0f [2] c1 17 [2] 86 15 [2] c1 04 [2] 8f 08 [2] 83 02 [2] 94 09 [2] 8f 47 [2] b2 }

  condition:
    any of them
}