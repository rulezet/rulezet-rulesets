rule TTP_XOR_MULT_DOSStub_0837 {
  strings:
    $key_0837 = { 5c 5f [2] 28 47 [2] 6f 45 [2] 28 54 [2] 66 58 [2] 6a 52 [2] 7d 59 [2] 66 17 [2] 5b }

  condition:
    any of them
}