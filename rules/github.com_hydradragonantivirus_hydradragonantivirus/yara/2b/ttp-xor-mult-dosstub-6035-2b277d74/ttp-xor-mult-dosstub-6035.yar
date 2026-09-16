rule TTP_XOR_MULT_DOSStub_6035 {
  strings:
    $key_6035 = { 34 5d [2] 40 45 [2] 07 47 [2] 40 56 [2] 0e 5a [2] 02 50 [2] 15 5b [2] 0e 15 [2] 33 }

  condition:
    any of them
}