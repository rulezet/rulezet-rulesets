rule TTP_XOR_MULT_DOSStub_3220 {
  strings:
    $key_3220 = { 66 48 [2] 12 50 [2] 55 52 [2] 12 43 [2] 5c 4f [2] 50 45 [2] 47 4e [2] 5c 00 [2] 61 }

  condition:
    any of them
}