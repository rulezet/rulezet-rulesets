rule TTP_XOR_MULT_DOSStub_ff96 {
  strings:
    $key_ff96 = { ab fe [2] df e6 [2] 98 e4 [2] df f5 [2] 91 f9 [2] 9d f3 [2] 8a f8 [2] 91 b6 [2] ac }

  condition:
    any of them
}