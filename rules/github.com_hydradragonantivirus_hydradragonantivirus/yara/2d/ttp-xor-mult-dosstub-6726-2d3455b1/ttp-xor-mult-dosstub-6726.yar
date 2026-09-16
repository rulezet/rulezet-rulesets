rule TTP_XOR_MULT_DOSStub_6726 {
  strings:
    $key_6726 = { 33 4e [2] 47 56 [2] 00 54 [2] 47 45 [2] 09 49 [2] 05 43 [2] 12 48 [2] 09 06 [2] 34 }

  condition:
    any of them
}