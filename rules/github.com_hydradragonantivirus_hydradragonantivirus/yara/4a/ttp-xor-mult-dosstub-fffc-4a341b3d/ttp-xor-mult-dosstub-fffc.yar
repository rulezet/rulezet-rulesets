rule TTP_XOR_MULT_DOSStub_fffc {
  strings:
    $key_fffc = { ab 94 [2] df 8c [2] 98 8e [2] df 9f [2] 91 93 [2] 9d 99 [2] 8a 92 [2] 91 dc [2] ac }

  condition:
    any of them
}