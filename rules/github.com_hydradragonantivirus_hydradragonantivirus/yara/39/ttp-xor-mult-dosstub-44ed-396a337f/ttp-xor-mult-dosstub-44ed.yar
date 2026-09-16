rule TTP_XOR_MULT_DOSStub_44ed {
  strings:
    $key_44ed = { 10 85 [2] 64 9d [2] 23 9f [2] 64 8e [2] 2a 82 [2] 26 88 [2] 31 83 [2] 2a cd [2] 17 }

  condition:
    any of them
}