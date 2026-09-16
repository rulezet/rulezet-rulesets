rule TTP_XOR_MULT_DOSStub_017b {
  strings:
    $key_017b = { 55 13 [2] 21 0b [2] 66 09 [2] 21 18 [2] 6f 14 [2] 63 1e [2] 74 15 [2] 6f 5b [2] 52 }

  condition:
    any of them
}