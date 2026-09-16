rule TTP_XOR_MULT_DOSStub_122b {
  strings:
    $key_122b = { 46 43 [2] 32 5b [2] 75 59 [2] 32 48 [2] 7c 44 [2] 70 4e [2] 67 45 [2] 7c 0b [2] 41 }

  condition:
    any of them
}