rule TTP_XOR_MULT_DOSStub_3024 {
  strings:
    $key_3024 = { 64 4c [2] 10 54 [2] 57 56 [2] 10 47 [2] 5e 4b [2] 52 41 [2] 45 4a [2] 5e 04 [2] 63 }

  condition:
    any of them
}