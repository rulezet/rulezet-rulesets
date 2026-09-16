rule TTP_XOR_MULT_DOSStub_3eae {
  strings:
    $key_3eae = { 6a c6 [2] 1e de [2] 59 dc [2] 1e cd [2] 50 c1 [2] 5c cb [2] 4b c0 [2] 50 8e [2] 6d }

  condition:
    any of them
}