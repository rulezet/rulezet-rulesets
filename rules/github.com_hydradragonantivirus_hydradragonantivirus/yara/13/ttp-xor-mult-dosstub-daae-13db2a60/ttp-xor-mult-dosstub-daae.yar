rule TTP_XOR_MULT_DOSStub_daae {
  strings:
    $key_daae = { 8e c6 [2] fa de [2] bd dc [2] fa cd [2] b4 c1 [2] b8 cb [2] af c0 [2] b4 8e [2] 89 }

  condition:
    any of them
}