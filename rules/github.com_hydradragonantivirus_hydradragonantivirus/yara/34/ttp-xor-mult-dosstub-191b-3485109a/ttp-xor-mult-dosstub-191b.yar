rule TTP_XOR_MULT_DOSStub_191b {
  strings:
    $key_191b = { 4d 73 [2] 39 6b [2] 7e 69 [2] 39 78 [2] 77 74 [2] 7b 7e [2] 6c 75 [2] 77 3b [2] 4a }

  condition:
    any of them
}