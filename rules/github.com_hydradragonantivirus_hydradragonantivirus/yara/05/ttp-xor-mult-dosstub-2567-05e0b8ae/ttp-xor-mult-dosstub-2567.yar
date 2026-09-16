rule TTP_XOR_MULT_DOSStub_2567 {
  strings:
    $key_2567 = { 71 0f [2] 05 17 [2] 42 15 [2] 05 04 [2] 4b 08 [2] 47 02 [2] 50 09 [2] 4b 47 [2] 76 }

  condition:
    any of them
}