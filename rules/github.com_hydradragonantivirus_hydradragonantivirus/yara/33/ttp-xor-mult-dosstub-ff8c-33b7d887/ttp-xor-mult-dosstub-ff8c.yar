rule TTP_XOR_MULT_DOSStub_ff8c {
  strings:
    $key_ff8c = { ab e4 [2] df fc [2] 98 fe [2] df ef [2] 91 e3 [2] 9d e9 [2] 8a e2 [2] 91 ac [2] ac }

  condition:
    any of them
}