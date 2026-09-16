rule TTP_XOR_MULT_DOSStub_015b {
  strings:
    $key_015b = { 55 33 [2] 21 2b [2] 66 29 [2] 21 38 [2] 6f 34 [2] 63 3e [2] 74 35 [2] 6f 7b [2] 52 }

  condition:
    any of them
}