rule TTP_XOR_MULT_DOSStub_3171 {
  strings:
    $key_3171 = { 65 19 [2] 11 01 [2] 56 03 [2] 11 12 [2] 5f 1e [2] 53 14 [2] 44 1f [2] 5f 51 [2] 62 }

  condition:
    any of them
}