rule TTP_XOR_MULT_DOSStub_023b {
  strings:
    $key_023b = { 56 53 [2] 22 4b [2] 65 49 [2] 22 58 [2] 6c 54 [2] 60 5e [2] 77 55 [2] 6c 1b [2] 51 }

  condition:
    any of them
}