rule TTP_XOR_MULT_DOSStub_ffb2 {
  strings:
    $key_ffb2 = { ab da [2] df c2 [2] 98 c0 [2] df d1 [2] 91 dd [2] 9d d7 [2] 8a dc [2] 91 92 [2] ac }

  condition:
    any of them
}