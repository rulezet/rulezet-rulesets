rule TTP_XOR_MULT_DOSStub_ff9b {
  strings:
    $key_ff9b = { ab f3 [2] df eb [2] 98 e9 [2] df f8 [2] 91 f4 [2] 9d fe [2] 8a f5 [2] 91 bb [2] ac }

  condition:
    any of them
}