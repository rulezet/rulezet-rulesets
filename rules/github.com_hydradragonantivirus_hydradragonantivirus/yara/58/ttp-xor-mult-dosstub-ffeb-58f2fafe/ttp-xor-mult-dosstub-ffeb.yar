rule TTP_XOR_MULT_DOSStub_ffeb {
  strings:
    $key_ffeb = { ab 83 [2] df 9b [2] 98 99 [2] df 88 [2] 91 84 [2] 9d 8e [2] 8a 85 [2] 91 cb [2] ac }

  condition:
    any of them
}