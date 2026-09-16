rule TTP_XOR_MULT_DOSStub_2b3b {
  strings:
    $key_2b3b = { 7f 53 [2] 0b 4b [2] 4c 49 [2] 0b 58 [2] 45 54 [2] 49 5e [2] 5e 55 [2] 45 1b [2] 78 }

  condition:
    any of them
}