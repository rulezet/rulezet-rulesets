rule TTP_XOR_MULT_DOSStub_2235 {
  strings:
    $key_2235 = { 76 5d [2] 02 45 [2] 45 47 [2] 02 56 [2] 4c 5a [2] 40 50 [2] 57 5b [2] 4c 15 [2] 71 }

  condition:
    any of them
}