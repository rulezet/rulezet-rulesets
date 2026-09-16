rule TTP_XOR_MULT_DOSStub_ffb8 {
  strings:
    $key_ffb8 = { ab d0 [2] df c8 [2] 98 ca [2] df db [2] 91 d7 [2] 9d dd [2] 8a d6 [2] 91 98 [2] ac }

  condition:
    any of them
}