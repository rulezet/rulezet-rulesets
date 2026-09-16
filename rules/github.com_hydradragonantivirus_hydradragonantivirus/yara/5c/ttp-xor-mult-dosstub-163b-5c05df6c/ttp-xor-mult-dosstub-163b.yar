rule TTP_XOR_MULT_DOSStub_163b {
  strings:
    $key_163b = { 42 53 [2] 36 4b [2] 71 49 [2] 36 58 [2] 78 54 [2] 74 5e [2] 63 55 [2] 78 1b [2] 45 }

  condition:
    any of them
}