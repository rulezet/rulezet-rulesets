rule TTP_XOR_MULT_DOSStub_2b1b {
  strings:
    $key_2b1b = { 7f 73 [2] 0b 6b [2] 4c 69 [2] 0b 78 [2] 45 74 [2] 49 7e [2] 5e 75 [2] 45 3b [2] 78 }

  condition:
    any of them
}