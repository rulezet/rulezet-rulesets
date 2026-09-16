rule TTP_XOR_MULT_DOSStub_06bc {
  strings:
    $key_06bc = { 52 d4 [2] 26 cc [2] 61 ce [2] 26 df [2] 68 d3 [2] 64 d9 [2] 73 d2 [2] 68 9c [2] 55 }

  condition:
    any of them
}