rule TTP_XOR_MULT_DOSStub_722b {
  strings:
    $key_722b = { 26 43 [2] 52 5b [2] 15 59 [2] 52 48 [2] 1c 44 [2] 10 4e [2] 07 45 [2] 1c 0b [2] 21 }

  condition:
    any of them
}