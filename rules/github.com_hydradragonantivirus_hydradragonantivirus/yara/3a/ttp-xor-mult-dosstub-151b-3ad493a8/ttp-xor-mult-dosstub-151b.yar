rule TTP_XOR_MULT_DOSStub_151b {
  strings:
    $key_151b = { 41 73 [2] 35 6b [2] 72 69 [2] 35 78 [2] 7b 74 [2] 77 7e [2] 60 75 [2] 7b 3b [2] 46 }

  condition:
    any of them
}