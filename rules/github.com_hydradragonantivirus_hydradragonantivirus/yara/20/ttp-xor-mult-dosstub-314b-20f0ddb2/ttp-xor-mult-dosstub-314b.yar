rule TTP_XOR_MULT_DOSStub_314b {
  strings:
    $key_314b = { 65 23 [2] 11 3b [2] 56 39 [2] 11 28 [2] 5f 24 [2] 53 2e [2] 44 25 [2] 5f 6b [2] 62 }

  condition:
    any of them
}