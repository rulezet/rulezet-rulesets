rule TTP_XOR_MULT_DOSStub_017c {
  strings:
    $key_017c = { 55 14 [2] 21 0c [2] 66 0e [2] 21 1f [2] 6f 13 [2] 63 19 [2] 74 12 [2] 6f 5c [2] 52 }

  condition:
    any of them
}