rule TTP_XOR_MULT_DOSStub_2443 {
  strings:
    $key_2443 = { 70 2b [2] 04 33 [2] 43 31 [2] 04 20 [2] 4a 2c [2] 46 26 [2] 51 2d [2] 4a 63 [2] 77 }

  condition:
    any of them
}