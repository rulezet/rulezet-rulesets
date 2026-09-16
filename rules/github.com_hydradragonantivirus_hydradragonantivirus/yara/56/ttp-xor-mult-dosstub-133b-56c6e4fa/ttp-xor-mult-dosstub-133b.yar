rule TTP_XOR_MULT_DOSStub_133b {
  strings:
    $key_133b = { 47 53 [2] 33 4b [2] 74 49 [2] 33 58 [2] 7d 54 [2] 71 5e [2] 66 55 [2] 7d 1b [2] 40 }

  condition:
    any of them
}