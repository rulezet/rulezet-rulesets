rule TTP_XOR_MULT_DOSStub_0513 {
  strings:
    $key_0513 = { 51 7b [2] 25 63 [2] 62 61 [2] 25 70 [2] 6b 7c [2] 67 76 [2] 70 7d [2] 6b 33 [2] 56 }

  condition:
    any of them
}