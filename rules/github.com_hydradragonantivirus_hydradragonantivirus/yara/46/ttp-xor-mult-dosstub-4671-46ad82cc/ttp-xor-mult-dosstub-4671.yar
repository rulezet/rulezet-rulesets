rule TTP_XOR_MULT_DOSStub_4671 {
  strings:
    $key_4671 = { 12 19 [2] 66 01 [2] 21 03 [2] 66 12 [2] 28 1e [2] 24 14 [2] 33 1f [2] 28 51 [2] 15 }

  condition:
    any of them
}