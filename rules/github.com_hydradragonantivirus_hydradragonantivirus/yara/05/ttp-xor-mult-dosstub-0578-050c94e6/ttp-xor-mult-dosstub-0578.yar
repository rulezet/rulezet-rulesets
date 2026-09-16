rule TTP_XOR_MULT_DOSStub_0578 {
  strings:
    $key_0578 = { 51 10 [2] 25 08 [2] 62 0a [2] 25 1b [2] 6b 17 [2] 67 1d [2] 70 16 [2] 6b 58 [2] 56 }

  condition:
    any of them
}