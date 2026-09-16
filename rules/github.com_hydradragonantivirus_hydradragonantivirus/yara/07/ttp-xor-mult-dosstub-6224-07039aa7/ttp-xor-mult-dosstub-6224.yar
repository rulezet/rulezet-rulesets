rule TTP_XOR_MULT_DOSStub_6224 {
  strings:
    $key_6224 = { 36 4c [2] 42 54 [2] 05 56 [2] 42 47 [2] 0c 4b [2] 00 41 [2] 17 4a [2] 0c 04 [2] 31 }

  condition:
    any of them
}