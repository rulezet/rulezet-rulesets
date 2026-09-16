rule TTP_XOR_MULT_DOSStub_00ed {
  strings:
    $key_00ed = { 54 85 [2] 20 9d [2] 67 9f [2] 20 8e [2] 6e 82 [2] 62 88 [2] 75 83 [2] 6e cd [2] 53 }

  condition:
    any of them
}