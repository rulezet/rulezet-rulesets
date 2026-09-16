rule TTP_XOR_MULT_DOSStub_27bc {
  strings:
    $key_27bc = { 73 d4 [2] 07 cc [2] 40 ce [2] 07 df [2] 49 d3 [2] 45 d9 [2] 52 d2 [2] 49 9c [2] 74 }

  condition:
    any of them
}