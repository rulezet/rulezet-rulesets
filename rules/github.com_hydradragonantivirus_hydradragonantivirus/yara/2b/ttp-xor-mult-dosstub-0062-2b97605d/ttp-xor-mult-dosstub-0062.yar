rule TTP_XOR_MULT_DOSStub_0062 {
  strings:
    $key_0062 = { 54 0a [2] 20 12 [2] 67 10 [2] 20 01 [2] 6e 0d [2] 62 07 [2] 75 0c [2] 6e 42 [2] 53 }

  condition:
    any of them
}