rule TTP_XOR_MULT_DOSStub_ffa8 {
  strings:
    $key_ffa8 = { ab c0 [2] df d8 [2] 98 da [2] df cb [2] 91 c7 [2] 9d cd [2] 8a c6 [2] 91 88 [2] ac }

  condition:
    any of them
}