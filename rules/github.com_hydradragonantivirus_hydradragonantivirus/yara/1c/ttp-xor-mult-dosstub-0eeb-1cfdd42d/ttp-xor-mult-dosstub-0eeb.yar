rule TTP_XOR_MULT_DOSStub_0eeb {
  strings:
    $key_0eeb = { 5a 83 [2] 2e 9b [2] 69 99 [2] 2e 88 [2] 60 84 [2] 6c 8e [2] 7b 85 [2] 60 cb [2] 5d }

  condition:
    any of them
}