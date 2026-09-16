rule TTP_XOR_MULT_DOSStub_027b {
  strings:
    $key_027b = { 56 13 [2] 22 0b [2] 65 09 [2] 22 18 [2] 6c 14 [2] 60 1e [2] 77 15 [2] 6c 5b [2] 51 }

  condition:
    any of them
}