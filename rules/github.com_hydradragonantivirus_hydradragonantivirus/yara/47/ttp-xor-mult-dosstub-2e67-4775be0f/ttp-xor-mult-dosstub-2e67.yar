rule TTP_XOR_MULT_DOSStub_2e67 {
  strings:
    $key_2e67 = { 7a 0f [2] 0e 17 [2] 49 15 [2] 0e 04 [2] 40 08 [2] 4c 02 [2] 5b 09 [2] 40 47 [2] 7d }

  condition:
    any of them
}