rule TTP_XOR_MULT_DOSStub_82bc {
  strings:
    $key_82bc = { d6 d4 [2] a2 cc [2] e5 ce [2] a2 df [2] ec d3 [2] e0 d9 [2] f7 d2 [2] ec 9c [2] d1 }

  condition:
    any of them
}