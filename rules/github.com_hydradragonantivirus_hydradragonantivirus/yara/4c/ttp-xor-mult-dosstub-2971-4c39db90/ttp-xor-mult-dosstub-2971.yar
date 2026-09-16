rule TTP_XOR_MULT_DOSStub_2971 {
  strings:
    $key_2971 = { 7d 19 [2] 09 01 [2] 4e 03 [2] 09 12 [2] 47 1e [2] 4b 14 [2] 5c 1f [2] 47 51 [2] 7a }

  condition:
    any of them
}