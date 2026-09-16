rule TTP_XOR_MULT_DOSStub_16bc {
  strings:
    $key_16bc = { 42 d4 [2] 36 cc [2] 71 ce [2] 36 df [2] 78 d3 [2] 74 d9 [2] 63 d2 [2] 78 9c [2] 45 }

  condition:
    any of them
}