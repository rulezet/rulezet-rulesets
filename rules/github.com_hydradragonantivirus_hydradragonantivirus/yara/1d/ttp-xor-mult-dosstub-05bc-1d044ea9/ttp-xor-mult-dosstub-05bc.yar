rule TTP_XOR_MULT_DOSStub_05bc {
  strings:
    $key_05bc = { 51 d4 [2] 25 cc [2] 62 ce [2] 25 df [2] 6b d3 [2] 67 d9 [2] 70 d2 [2] 6b 9c [2] 56 }

  condition:
    any of them
}