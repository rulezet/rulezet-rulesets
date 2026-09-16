rule TTP_XOR_MULT_DOSStub_5669 {
  strings:
    $key_5669 = { 02 01 [2] 76 19 [2] 31 1b [2] 76 0a [2] 38 06 [2] 34 0c [2] 23 07 [2] 38 49 [2] 05 }

  condition:
    any of them
}