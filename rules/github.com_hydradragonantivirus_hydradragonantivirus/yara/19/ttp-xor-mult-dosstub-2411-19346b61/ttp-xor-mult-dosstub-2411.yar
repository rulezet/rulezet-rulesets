rule TTP_XOR_MULT_DOSStub_2411 {
  strings:
    $key_2411 = { 70 79 [2] 04 61 [2] 43 63 [2] 04 72 [2] 4a 7e [2] 46 74 [2] 51 7f [2] 4a 31 [2] 77 }

  condition:
    any of them
}