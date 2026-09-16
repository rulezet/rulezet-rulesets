rule TTP_XOR_MULT_DOSStub_721b {
  strings:
    $key_721b = { 26 73 [2] 52 6b [2] 15 69 [2] 52 78 [2] 1c 74 [2] 10 7e [2] 07 75 [2] 1c 3b [2] 21 }

  condition:
    any of them
}