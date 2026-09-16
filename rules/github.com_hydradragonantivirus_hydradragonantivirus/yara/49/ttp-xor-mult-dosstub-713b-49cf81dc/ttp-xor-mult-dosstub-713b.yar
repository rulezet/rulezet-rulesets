rule TTP_XOR_MULT_DOSStub_713b {
  strings:
    $key_713b = { 25 53 [2] 51 4b [2] 16 49 [2] 51 58 [2] 1f 54 [2] 13 5e [2] 04 55 [2] 1f 1b [2] 22 }

  condition:
    any of them
}