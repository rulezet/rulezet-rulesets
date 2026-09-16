rule TTP_XOR_MULT_DOSStub_042b {
  strings:
    $key_042b = { 50 43 [2] 24 5b [2] 63 59 [2] 24 48 [2] 6a 44 [2] 66 4e [2] 71 45 [2] 6a 0b [2] 57 }

  condition:
    any of them
}