rule TTP_XOR_MULT_DOSStub_0a6b {
  strings:
    $key_0a6b = { 5e 03 [2] 2a 1b [2] 6d 19 [2] 2a 08 [2] 64 04 [2] 68 0e [2] 7f 05 [2] 64 4b [2] 59 }

  condition:
    any of them
}