rule TTP_XOR_MULT_DOSStub_e017 {
  strings:
    $key_e017 = { b4 7f [2] c0 67 [2] 87 65 [2] c0 74 [2] 8e 78 [2] 82 72 [2] 95 79 [2] 8e 37 [2] b3 }

  condition:
    any of them
}