rule TTP_XOR_MULT_DOSStub_2900 {
  strings:
    $key_2900 = { 7d 68 [2] 09 70 [2] 4e 72 [2] 09 63 [2] 47 6f [2] 4b 65 [2] 5c 6e [2] 47 20 [2] 7a }

  condition:
    any of them
}