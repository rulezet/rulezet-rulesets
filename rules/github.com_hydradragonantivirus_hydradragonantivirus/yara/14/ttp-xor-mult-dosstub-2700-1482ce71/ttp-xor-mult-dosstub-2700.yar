rule TTP_XOR_MULT_DOSStub_2700 {
  strings:
    $key_2700 = { 73 68 [2] 07 70 [2] 40 72 [2] 07 63 [2] 49 6f [2] 45 65 [2] 52 6e [2] 49 20 [2] 74 }

  condition:
    any of them
}