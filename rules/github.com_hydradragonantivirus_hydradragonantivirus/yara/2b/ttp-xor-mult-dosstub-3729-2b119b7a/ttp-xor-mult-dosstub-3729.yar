rule TTP_XOR_MULT_DOSStub_3729 {
  strings:
    $key_3729 = { 63 41 [2] 17 59 [2] 50 5b [2] 17 4a [2] 59 46 [2] 55 4c [2] 42 47 [2] 59 09 [2] 64 }

  condition:
    any of them
}