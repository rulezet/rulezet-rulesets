rule TTP_XOR_MULT_DOSStub_04ed {
  strings:
    $key_04ed = { 50 85 [2] 24 9d [2] 63 9f [2] 24 8e [2] 6a 82 [2] 66 88 [2] 71 83 [2] 6a cd [2] 57 }

  condition:
    any of them
}