rule TTP_XOR_MULT_DOSStub_113b {
  strings:
    $key_113b = { 45 53 [2] 31 4b [2] 76 49 [2] 31 58 [2] 7f 54 [2] 73 5e [2] 64 55 [2] 7f 1b [2] 42 }

  condition:
    any of them
}