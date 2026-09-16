rule TTP_XOR_MULT_DOSStub_ffa9 {
  strings:
    $key_ffa9 = { ab c1 [2] df d9 [2] 98 db [2] df ca [2] 91 c6 [2] 9d cc [2] 8a c7 [2] 91 89 [2] ac }

  condition:
    any of them
}