rule TTP_XOR_MULT_DOSStub_347b {
  strings:
    $key_347b = { 60 13 [2] 14 0b [2] 53 09 [2] 14 18 [2] 5a 14 [2] 56 1e [2] 41 15 [2] 5a 5b [2] 67 }

  condition:
    any of them
}