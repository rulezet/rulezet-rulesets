rule TTP_XOR_MULT_DOSStub_2578 {
  strings:
    $key_2578 = { 71 10 [2] 05 08 [2] 42 0a [2] 05 1b [2] 4b 17 [2] 47 1d [2] 50 16 [2] 4b 58 [2] 76 }

  condition:
    any of them
}