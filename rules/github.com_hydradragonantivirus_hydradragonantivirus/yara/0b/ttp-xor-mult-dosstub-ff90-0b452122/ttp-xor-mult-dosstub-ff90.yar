rule TTP_XOR_MULT_DOSStub_ff90 {
  strings:
    $key_ff90 = { ab f8 [2] df e0 [2] 98 e2 [2] df f3 [2] 91 ff [2] 9d f5 [2] 8a fe [2] 91 b0 [2] ac }

  condition:
    any of them
}