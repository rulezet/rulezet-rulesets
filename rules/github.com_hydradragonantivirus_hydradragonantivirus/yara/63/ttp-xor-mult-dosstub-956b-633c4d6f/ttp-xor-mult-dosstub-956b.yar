rule TTP_XOR_MULT_DOSStub_956b {
  strings:
    $key_956b = { c1 03 [2] b5 1b [2] f2 19 [2] b5 08 [2] fb 04 [2] f7 0e [2] e0 05 [2] fb 4b [2] c6 }

  condition:
    any of them
}