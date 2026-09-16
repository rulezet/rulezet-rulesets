rule TTP_XOR_MULT_DOSStub_27e7 {
  strings:
    $key_27e7 = { 73 8f [2] 07 97 [2] 40 95 [2] 07 84 [2] 49 88 [2] 45 82 [2] 52 89 [2] 49 c7 [2] 74 }

  condition:
    any of them
}