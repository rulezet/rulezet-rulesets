rule TTP_XOR_MULT_DOSStub_ccac {
  strings:
    $key_ccac = { 98 c4 [2] ec dc [2] ab de [2] ec cf [2] a2 c3 [2] ae c9 [2] b9 c2 [2] a2 8c [2] 9f }

  condition:
    any of them
}