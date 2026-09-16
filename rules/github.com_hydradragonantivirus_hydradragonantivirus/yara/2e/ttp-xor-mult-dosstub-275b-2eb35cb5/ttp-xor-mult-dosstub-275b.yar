rule TTP_XOR_MULT_DOSStub_275b {
  strings:
    $key_275b = { 73 33 [2] 07 2b [2] 40 29 [2] 07 38 [2] 49 34 [2] 45 3e [2] 52 35 [2] 49 7b [2] 74 }

  condition:
    any of them
}