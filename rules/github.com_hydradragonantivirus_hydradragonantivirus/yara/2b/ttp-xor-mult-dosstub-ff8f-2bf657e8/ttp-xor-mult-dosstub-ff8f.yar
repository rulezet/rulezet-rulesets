rule TTP_XOR_MULT_DOSStub_ff8f {
  strings:
    $key_ff8f = { ab e7 [2] df ff [2] 98 fd [2] df ec [2] 91 e0 [2] 9d ea [2] 8a e1 [2] 91 af [2] ac }

  condition:
    any of them
}