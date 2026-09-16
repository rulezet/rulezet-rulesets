rule TTP_XOR_MULT_DOSStub_0a3b {
  strings:
    $key_0a3b = { 5e 53 [2] 2a 4b [2] 6d 49 [2] 2a 58 [2] 64 54 [2] 68 5e [2] 7f 55 [2] 64 1b [2] 59 }

  condition:
    any of them
}