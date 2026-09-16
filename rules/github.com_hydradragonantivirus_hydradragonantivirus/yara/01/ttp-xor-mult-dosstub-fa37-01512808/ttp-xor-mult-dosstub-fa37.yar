rule TTP_XOR_MULT_DOSStub_fa37 {
  strings:
    $key_fa37 = { ae 5f [2] da 47 [2] 9d 45 [2] da 54 [2] 94 58 [2] 98 52 [2] 8f 59 [2] 94 17 [2] a9 }

  condition:
    any of them
}