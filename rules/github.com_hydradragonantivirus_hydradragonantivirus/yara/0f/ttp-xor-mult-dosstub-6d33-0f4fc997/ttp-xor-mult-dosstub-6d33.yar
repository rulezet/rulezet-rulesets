rule TTP_XOR_MULT_DOSStub_6d33 {
  strings:
    $key_6d33 = { 39 5b [2] 4d 43 [2] 0a 41 [2] 4d 50 [2] 03 5c [2] 0f 56 [2] 18 5d [2] 03 13 [2] 3e }

  condition:
    any of them
}