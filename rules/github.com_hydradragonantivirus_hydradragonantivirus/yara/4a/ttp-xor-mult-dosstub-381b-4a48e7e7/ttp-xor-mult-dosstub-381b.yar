rule TTP_XOR_MULT_DOSStub_381b {
  strings:
    $key_381b = { 6c 73 [2] 18 6b [2] 5f 69 [2] 18 78 [2] 56 74 [2] 5a 7e [2] 4d 75 [2] 56 3b [2] 6b }

  condition:
    any of them
}