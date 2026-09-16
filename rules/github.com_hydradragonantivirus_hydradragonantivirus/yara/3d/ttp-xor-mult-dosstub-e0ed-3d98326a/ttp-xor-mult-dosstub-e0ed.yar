rule TTP_XOR_MULT_DOSStub_e0ed {
  strings:
    $key_e0ed = { b4 85 [2] c0 9d [2] 87 9f [2] c0 8e [2] 8e 82 [2] 82 88 [2] 95 83 [2] 8e cd [2] b3 }

  condition:
    any of them
}