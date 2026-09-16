rule TTP_XOR_MULT_DOSStub_0971 {
  strings:
    $key_0971 = { 5d 19 [2] 29 01 [2] 6e 03 [2] 29 12 [2] 67 1e [2] 6b 14 [2] 7c 1f [2] 67 51 [2] 5a }

  condition:
    any of them
}