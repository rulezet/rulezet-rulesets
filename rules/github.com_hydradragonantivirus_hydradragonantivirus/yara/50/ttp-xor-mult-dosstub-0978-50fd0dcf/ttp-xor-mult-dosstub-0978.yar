rule TTP_XOR_MULT_DOSStub_0978 {
  strings:
    $key_0978 = { 5d 10 [2] 29 08 [2] 6e 0a [2] 29 1b [2] 67 17 [2] 6b 1d [2] 7c 16 [2] 67 58 [2] 5a }

  condition:
    any of them
}