rule TTP_XOR_MULT_DOSStub_2613 {
  strings:
    $key_2613 = { 72 7b [2] 06 63 [2] 41 61 [2] 06 70 [2] 48 7c [2] 44 76 [2] 53 7d [2] 48 33 [2] 75 }

  condition:
    any of them
}