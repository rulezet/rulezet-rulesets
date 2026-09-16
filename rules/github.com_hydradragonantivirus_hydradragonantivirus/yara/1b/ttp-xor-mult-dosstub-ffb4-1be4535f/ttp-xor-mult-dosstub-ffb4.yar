rule TTP_XOR_MULT_DOSStub_ffb4 {
  strings:
    $key_ffb4 = { ab dc [2] df c4 [2] 98 c6 [2] df d7 [2] 91 db [2] 9d d1 [2] 8a da [2] 91 94 [2] ac }

  condition:
    any of them
}