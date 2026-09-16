rule TTP_XOR_MULT_DOSStub_34eb {
  strings:
    $key_34eb = { 60 83 [2] 14 9b [2] 53 99 [2] 14 88 [2] 5a 84 [2] 56 8e [2] 41 85 [2] 5a cb [2] 67 }

  condition:
    any of them
}