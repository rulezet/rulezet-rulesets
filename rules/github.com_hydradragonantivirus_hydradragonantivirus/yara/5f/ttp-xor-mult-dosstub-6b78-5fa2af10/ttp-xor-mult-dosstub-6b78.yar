rule TTP_XOR_MULT_DOSStub_6b78 {
  strings:
    $key_6b78 = { 3f 10 [2] 4b 08 [2] 0c 0a [2] 4b 1b [2] 05 17 [2] 09 1d [2] 1e 16 [2] 05 58 [2] 38 }

  condition:
    any of them
}