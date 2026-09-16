rule TTP_XOR_MULT_DOSStub_ffbe {
  strings:
    $key_ffbe = { ab d6 [2] df ce [2] 98 cc [2] df dd [2] 91 d1 [2] 9d db [2] 8a d0 [2] 91 9e [2] ac }

  condition:
    any of them
}