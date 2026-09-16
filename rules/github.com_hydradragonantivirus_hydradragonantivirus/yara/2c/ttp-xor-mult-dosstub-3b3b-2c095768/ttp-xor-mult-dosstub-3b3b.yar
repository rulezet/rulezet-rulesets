rule TTP_XOR_MULT_DOSStub_3b3b {
  strings:
    $key_3b3b = { 6f 53 [2] 1b 4b [2] 5c 49 [2] 1b 58 [2] 55 54 [2] 59 5e [2] 4e 55 [2] 55 1b [2] 68 }

  condition:
    any of them
}