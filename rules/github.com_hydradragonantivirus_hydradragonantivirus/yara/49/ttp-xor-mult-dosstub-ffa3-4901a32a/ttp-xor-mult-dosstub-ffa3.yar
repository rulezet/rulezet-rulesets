rule TTP_XOR_MULT_DOSStub_ffa3 {
  strings:
    $key_ffa3 = { ab cb [2] df d3 [2] 98 d1 [2] df c0 [2] 91 cc [2] 9d c6 [2] 8a cd [2] 91 83 [2] ac }

  condition:
    any of them
}