rule TTP_XOR_MULT_DOSStub_57e5 {
  strings:
    $key_57e5 = { 03 8d [2] 77 95 [2] 30 97 [2] 77 86 [2] 39 8a [2] 35 80 [2] 22 8b [2] 39 c5 [2] 04 }

  condition:
    any of them
}