rule TTP_XOR_MULT_DOSStub_280b {
  strings:
    $key_280b = { 7c 63 [2] 08 7b [2] 4f 79 [2] 08 68 [2] 46 64 [2] 4a 6e [2] 5d 65 [2] 46 2b [2] 7b }

  condition:
    any of them
}