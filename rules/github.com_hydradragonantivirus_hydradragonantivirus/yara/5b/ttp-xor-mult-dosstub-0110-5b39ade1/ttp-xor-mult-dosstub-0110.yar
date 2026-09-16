rule TTP_XOR_MULT_DOSStub_0110 {
  strings:
    $key_0110 = { 55 78 [2] 21 60 [2] 66 62 [2] 21 73 [2] 6f 7f [2] 63 75 [2] 74 7e [2] 6f 30 [2] 52 }

  condition:
    any of them
}