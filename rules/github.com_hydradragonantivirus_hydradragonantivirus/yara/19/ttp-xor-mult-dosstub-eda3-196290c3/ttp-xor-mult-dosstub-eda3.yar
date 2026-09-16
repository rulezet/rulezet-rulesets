rule TTP_XOR_MULT_DOSStub_eda3 {
  strings:
    $key_eda3 = { b9 cb [2] cd d3 [2] 8a d1 [2] cd c0 [2] 83 cc [2] 8f c6 [2] 98 cd [2] 83 83 [2] be }

  condition:
    any of them
}