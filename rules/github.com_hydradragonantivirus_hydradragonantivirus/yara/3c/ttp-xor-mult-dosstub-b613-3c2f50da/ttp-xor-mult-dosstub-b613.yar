rule TTP_XOR_MULT_DOSStub_b613 {
  strings:
    $key_b613 = { e2 7b [2] 96 63 [2] d1 61 [2] 96 70 [2] d8 7c [2] d4 76 [2] c3 7d [2] d8 33 [2] e5 }

  condition:
    any of them
}