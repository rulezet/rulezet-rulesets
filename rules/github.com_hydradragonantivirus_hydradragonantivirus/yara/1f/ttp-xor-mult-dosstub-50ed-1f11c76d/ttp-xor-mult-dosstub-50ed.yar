rule TTP_XOR_MULT_DOSStub_50ed {
  strings:
    $key_50ed = { 04 85 [2] 70 9d [2] 37 9f [2] 70 8e [2] 3e 82 [2] 32 88 [2] 25 83 [2] 3e cd [2] 03 }

  condition:
    any of them
}