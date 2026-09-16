rule TTP_XOR_MULT_DOSStub_3be0 {
  strings:
    $key_3be0 = { 6f 88 [2] 1b 90 [2] 5c 92 [2] 1b 83 [2] 55 8f [2] 59 85 [2] 4e 8e [2] 55 c0 [2] 68 }

  condition:
    any of them
}