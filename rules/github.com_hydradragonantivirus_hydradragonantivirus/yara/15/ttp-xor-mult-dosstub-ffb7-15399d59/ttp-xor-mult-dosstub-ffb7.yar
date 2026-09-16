rule TTP_XOR_MULT_DOSStub_ffb7 {
  strings:
    $key_ffb7 = { ab df [2] df c7 [2] 98 c5 [2] df d4 [2] 91 d8 [2] 9d d2 [2] 8a d9 [2] 91 97 [2] ac }

  condition:
    any of them
}