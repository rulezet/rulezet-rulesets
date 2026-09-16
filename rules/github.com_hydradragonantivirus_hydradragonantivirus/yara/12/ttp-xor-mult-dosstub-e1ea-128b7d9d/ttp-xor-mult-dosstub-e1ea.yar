rule TTP_XOR_MULT_DOSStub_e1ea {
  strings:
    $key_e1ea = { b5 82 [2] c1 9a [2] 86 98 [2] c1 89 [2] 8f 85 [2] 83 8f [2] 94 84 [2] 8f ca [2] b2 }

  condition:
    any of them
}