rule TTP_XOR_MULT_DOSStub_c3bc {
  strings:
    $key_c3bc = { 97 d4 [2] e3 cc [2] a4 ce [2] e3 df [2] ad d3 [2] a1 d9 [2] b6 d2 [2] ad 9c [2] 90 }

  condition:
    any of them
}