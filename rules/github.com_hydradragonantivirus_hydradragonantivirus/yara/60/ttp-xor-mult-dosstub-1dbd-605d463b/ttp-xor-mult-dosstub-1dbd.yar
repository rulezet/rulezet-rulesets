rule TTP_XOR_MULT_DOSStub_1dbd {
  strings:
    $key_1dbd = { 49 d5 [2] 3d cd [2] 7a cf [2] 3d de [2] 73 d2 [2] 7f d8 [2] 68 d3 [2] 73 9d [2] 4e }

  condition:
    any of them
}