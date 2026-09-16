rule TTP_XOR_MULT_DOSStub_6a1b {
  strings:
    $key_6a1b = { 3e 73 [2] 4a 6b [2] 0d 69 [2] 4a 78 [2] 04 74 [2] 08 7e [2] 1f 75 [2] 04 3b [2] 39 }

  condition:
    any of them
}