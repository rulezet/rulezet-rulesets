rule TTP_XOR_MULT_DOSStub_e2ea {
  strings:
    $key_e2ea = { b6 82 [2] c2 9a [2] 85 98 [2] c2 89 [2] 8c 85 [2] 80 8f [2] 97 84 [2] 8c ca [2] b1 }

  condition:
    any of them
}