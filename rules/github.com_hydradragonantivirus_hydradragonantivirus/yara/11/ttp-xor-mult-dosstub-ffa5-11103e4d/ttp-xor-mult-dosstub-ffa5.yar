rule TTP_XOR_MULT_DOSStub_ffa5 {
  strings:
    $key_ffa5 = { ab cd [2] df d5 [2] 98 d7 [2] df c6 [2] 91 ca [2] 9d c0 [2] 8a cb [2] 91 85 [2] ac }

  condition:
    any of them
}