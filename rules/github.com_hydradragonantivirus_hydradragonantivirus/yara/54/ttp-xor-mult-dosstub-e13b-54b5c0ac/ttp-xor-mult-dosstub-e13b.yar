rule TTP_XOR_MULT_DOSStub_e13b {
  strings:
    $key_e13b = { b5 53 [2] c1 4b [2] 86 49 [2] c1 58 [2] 8f 54 [2] 83 5e [2] 94 55 [2] 8f 1b [2] b2 }

  condition:
    any of them
}