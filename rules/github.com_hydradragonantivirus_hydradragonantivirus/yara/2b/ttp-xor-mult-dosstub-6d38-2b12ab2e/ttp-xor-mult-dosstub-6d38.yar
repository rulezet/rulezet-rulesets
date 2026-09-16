rule TTP_XOR_MULT_DOSStub_6d38 {
  strings:
    $key_6d38 = { 39 50 [2] 4d 48 [2] 0a 4a [2] 4d 5b [2] 03 57 [2] 0f 5d [2] 18 56 [2] 03 18 [2] 3e }

  condition:
    any of them
}