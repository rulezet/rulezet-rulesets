rule TTP_XOR_MULT_DOSStub_e4ea {
  strings:
    $key_e4ea = { b0 82 [2] c4 9a [2] 83 98 [2] c4 89 [2] 8a 85 [2] 86 8f [2] 91 84 [2] 8a ca [2] b7 }

  condition:
    any of them
}