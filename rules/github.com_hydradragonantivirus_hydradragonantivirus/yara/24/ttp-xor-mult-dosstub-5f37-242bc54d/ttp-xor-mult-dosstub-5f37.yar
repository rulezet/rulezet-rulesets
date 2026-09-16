rule TTP_XOR_MULT_DOSStub_5f37 {
  strings:
    $key_5f37 = { 0b 5f [2] 7f 47 [2] 38 45 [2] 7f 54 [2] 31 58 [2] 3d 52 [2] 2a 59 [2] 31 17 [2] 0c }

  condition:
    any of them
}