rule TTP_XOR_MULT_DOSStub_2b78 {
  strings:
    $key_2b78 = { 7f 10 [2] 0b 08 [2] 4c 0a [2] 0b 1b [2] 45 17 [2] 49 1d [2] 5e 16 [2] 45 58 [2] 78 }

  condition:
    any of them
}