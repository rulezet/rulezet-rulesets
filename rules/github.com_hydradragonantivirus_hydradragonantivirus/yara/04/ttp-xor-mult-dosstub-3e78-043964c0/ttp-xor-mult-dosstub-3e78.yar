rule TTP_XOR_MULT_DOSStub_3e78 {
  strings:
    $key_3e78 = { 6a 10 [2] 1e 08 [2] 59 0a [2] 1e 1b [2] 50 17 [2] 5c 1d [2] 4b 16 [2] 50 58 [2] 6d }

  condition:
    any of them
}