rule TTP_XOR_MULT_DOSStub_695b {
  strings:
    $key_695b = { 3d 33 [2] 49 2b [2] 0e 29 [2] 49 38 [2] 07 34 [2] 0b 3e [2] 1c 35 [2] 07 7b [2] 3a }

  condition:
    any of them
}