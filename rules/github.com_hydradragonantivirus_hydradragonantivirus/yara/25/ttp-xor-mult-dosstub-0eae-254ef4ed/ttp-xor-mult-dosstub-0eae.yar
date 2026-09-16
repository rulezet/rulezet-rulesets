rule TTP_XOR_MULT_DOSStub_0eae {
  strings:
    $key_0eae = { 5a c6 [2] 2e de [2] 69 dc [2] 2e cd [2] 60 c1 [2] 6c cb [2] 7b c0 [2] 60 8e [2] 5d }

  condition:
    any of them
}