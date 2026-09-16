rule TTP_XOR_MULT_DOSStub_3eeb {
  strings:
    $key_3eeb = { 6a 83 [2] 1e 9b [2] 59 99 [2] 1e 88 [2] 50 84 [2] 5c 8e [2] 4b 85 [2] 50 cb [2] 6d }

  condition:
    any of them
}