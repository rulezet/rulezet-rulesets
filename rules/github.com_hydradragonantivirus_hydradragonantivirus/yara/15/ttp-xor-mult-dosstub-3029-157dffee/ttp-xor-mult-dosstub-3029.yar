rule TTP_XOR_MULT_DOSStub_3029 {
  strings:
    $key_3029 = { 64 41 [2] 10 59 [2] 57 5b [2] 10 4a [2] 5e 46 [2] 52 4c [2] 45 47 [2] 5e 09 [2] 63 }

  condition:
    any of them
}