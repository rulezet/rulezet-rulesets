rule TTP_XOR_MULT_DOSStub_6333 {
  strings:
    $key_6333 = { 37 5b [2] 43 43 [2] 04 41 [2] 43 50 [2] 0d 5c [2] 01 56 [2] 16 5d [2] 0d 13 [2] 30 }

  condition:
    any of them
}