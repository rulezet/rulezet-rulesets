rule TTP_XOR_MULT_DOSStub_fff7 {
  strings:
    $key_fff7 = { ab 9f [2] df 87 [2] 98 85 [2] df 94 [2] 91 98 [2] 9d 92 [2] 8a 99 [2] 91 d7 [2] ac }

  condition:
    any of them
}