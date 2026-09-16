rule TTP_XOR_MULT_DOSStub_ff86 {
  strings:
    $key_ff86 = { ab ee [2] df f6 [2] 98 f4 [2] df e5 [2] 91 e9 [2] 9d e3 [2] 8a e8 [2] 91 a6 [2] ac }

  condition:
    any of them
}