rule TTP_XOR_MULT_DOSStub_7b24 {
  strings:
    $key_7b24 = { 2f 4c [2] 5b 54 [2] 1c 56 [2] 5b 47 [2] 15 4b [2] 19 41 [2] 0e 4a [2] 15 04 [2] 28 }

  condition:
    any of them
}