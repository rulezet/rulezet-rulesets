rule TTP_XOR_MULT_DOSStub_3721 {
  strings:
    $key_3721 = { 63 49 [2] 17 51 [2] 50 53 [2] 17 42 [2] 59 4e [2] 55 44 [2] 42 4f [2] 59 01 [2] 64 }

  condition:
    any of them
}