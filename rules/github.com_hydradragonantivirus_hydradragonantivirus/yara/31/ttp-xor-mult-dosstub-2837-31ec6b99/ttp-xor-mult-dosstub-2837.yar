rule TTP_XOR_MULT_DOSStub_2837 {
  strings:
    $key_2837 = { 7c 5f [2] 08 47 [2] 4f 45 [2] 08 54 [2] 46 58 [2] 4a 52 [2] 5d 59 [2] 46 17 [2] 7b }

  condition:
    any of them
}