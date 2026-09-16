rule TTP_XOR_MULT_DOSStub_0029 {
  strings:
    $key_0029 = { 54 41 [2] 20 59 [2] 67 5b [2] 20 4a [2] 6e 46 [2] 62 4c [2] 75 47 [2] 6e 09 [2] 53 }

  condition:
    any of them
}