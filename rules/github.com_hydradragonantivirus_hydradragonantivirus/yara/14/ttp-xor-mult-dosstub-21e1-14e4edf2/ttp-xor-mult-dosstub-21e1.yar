rule TTP_XOR_MULT_DOSStub_21e1 {
  strings:
    $key_21e1 = { 75 89 [2] 01 91 [2] 46 93 [2] 01 82 [2] 4f 8e [2] 43 84 [2] 54 8f [2] 4f c1 [2] 72 }

  condition:
    any of them
}