rule TTP_XOR_MULT_DOSStub_ffa1 {
  strings:
    $key_ffa1 = { ab c9 [2] df d1 [2] 98 d3 [2] df c2 [2] 91 ce [2] 9d c4 [2] 8a cf [2] 91 81 [2] ac }

  condition:
    any of them
}