rule TTP_XOR_MULT_DOSStub_ffa0 {
  strings:
    $key_ffa0 = { ab c8 [2] df d0 [2] 98 d2 [2] df c3 [2] 91 cf [2] 9d c5 [2] 8a ce [2] 91 80 [2] ac }

  condition:
    any of them
}