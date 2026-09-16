rule TTP_XOR_MULT_DOSStub_6a5b {
  strings:
    $key_6a5b = { 3e 33 [2] 4a 2b [2] 0d 29 [2] 4a 38 [2] 04 34 [2] 08 3e [2] 1f 35 [2] 04 7b [2] 39 }

  condition:
    any of them
}