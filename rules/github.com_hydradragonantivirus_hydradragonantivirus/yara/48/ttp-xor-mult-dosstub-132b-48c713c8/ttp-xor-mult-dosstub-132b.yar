rule TTP_XOR_MULT_DOSStub_132b {
  strings:
    $key_132b = { 47 43 [2] 33 5b [2] 74 59 [2] 33 48 [2] 7d 44 [2] 71 4e [2] 66 45 [2] 7d 0b [2] 40 }

  condition:
    any of them
}