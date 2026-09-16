rule TTP_XOR_MULT_DOSStub_ffa4 {
  strings:
    $key_ffa4 = { ab cc [2] df d4 [2] 98 d6 [2] df c7 [2] 91 cb [2] 9d c1 [2] 8a ca [2] 91 84 [2] ac }

  condition:
    any of them
}