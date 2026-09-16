rule TTP_XOR_MULT_DOSStub_3224 {
  strings:
    $key_3224 = { 66 4c [2] 12 54 [2] 55 56 [2] 12 47 [2] 5c 4b [2] 50 41 [2] 47 4a [2] 5c 04 [2] 61 }

  condition:
    any of them
}