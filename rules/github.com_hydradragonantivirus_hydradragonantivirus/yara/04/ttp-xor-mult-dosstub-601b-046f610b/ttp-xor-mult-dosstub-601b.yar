rule TTP_XOR_MULT_DOSStub_601b {
  strings:
    $key_601b = { 34 73 [2] 40 6b [2] 07 69 [2] 40 78 [2] 0e 74 [2] 02 7e [2] 15 75 [2] 0e 3b [2] 33 }

  condition:
    any of them
}