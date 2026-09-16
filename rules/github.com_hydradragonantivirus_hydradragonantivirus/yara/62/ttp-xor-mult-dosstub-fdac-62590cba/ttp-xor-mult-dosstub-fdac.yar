rule TTP_XOR_MULT_DOSStub_fdac {
  strings:
    $key_fdac = { a9 c4 [2] dd dc [2] 9a de [2] dd cf [2] 93 c3 [2] 9f c9 [2] 88 c2 [2] 93 8c [2] ae }

  condition:
    any of them
}