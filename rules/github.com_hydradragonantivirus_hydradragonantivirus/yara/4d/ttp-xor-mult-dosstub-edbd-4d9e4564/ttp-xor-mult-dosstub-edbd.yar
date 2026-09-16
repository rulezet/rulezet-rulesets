rule TTP_XOR_MULT_DOSStub_edbd {
  strings:
    $key_edbd = { b9 d5 [2] cd cd [2] 8a cf [2] cd de [2] 83 d2 [2] 8f d8 [2] 98 d3 [2] 83 9d [2] be }

  condition:
    any of them
}