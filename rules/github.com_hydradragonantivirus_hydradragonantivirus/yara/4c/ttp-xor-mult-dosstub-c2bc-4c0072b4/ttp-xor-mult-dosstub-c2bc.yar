rule TTP_XOR_MULT_DOSStub_c2bc {
  strings:
    $key_c2bc = { 96 d4 [2] e2 cc [2] a5 ce [2] e2 df [2] ac d3 [2] a0 d9 [2] b7 d2 [2] ac 9c [2] 91 }

  condition:
    any of them
}