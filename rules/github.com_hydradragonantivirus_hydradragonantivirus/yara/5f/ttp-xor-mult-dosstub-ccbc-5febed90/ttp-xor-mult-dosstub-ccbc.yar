rule TTP_XOR_MULT_DOSStub_ccbc {
  strings:
    $key_ccbc = { 98 d4 [2] ec cc [2] ab ce [2] ec df [2] a2 d3 [2] ae d9 [2] b9 d2 [2] a2 9c [2] 9f }

  condition:
    any of them
}