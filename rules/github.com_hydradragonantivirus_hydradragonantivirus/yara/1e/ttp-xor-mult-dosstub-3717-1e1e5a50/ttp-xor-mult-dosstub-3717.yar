rule TTP_XOR_MULT_DOSStub_3717 {
  strings:
    $key_3717 = { 63 7f [2] 17 67 [2] 50 65 [2] 17 74 [2] 59 78 [2] 55 72 [2] 42 79 [2] 59 37 [2] 64 }

  condition:
    any of them
}