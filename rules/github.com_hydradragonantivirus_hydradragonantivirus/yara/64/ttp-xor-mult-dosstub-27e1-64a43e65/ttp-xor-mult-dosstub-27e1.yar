rule TTP_XOR_MULT_DOSStub_27e1 {
  strings:
    $key_27e1 = { 73 89 [2] 07 91 [2] 40 93 [2] 07 82 [2] 49 8e [2] 45 84 [2] 52 8f [2] 49 c1 [2] 74 }

  condition:
    any of them
}