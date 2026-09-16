rule TTP_XOR_MULT_DOSStub_347c {
  strings:
    $key_347c = { 60 14 [2] 14 0c [2] 53 0e [2] 14 1f [2] 5a 13 [2] 56 19 [2] 41 12 [2] 5a 5c [2] 67 }

  condition:
    any of them
}