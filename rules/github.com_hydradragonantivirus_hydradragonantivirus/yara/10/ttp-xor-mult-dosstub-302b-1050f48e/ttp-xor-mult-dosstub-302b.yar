rule TTP_XOR_MULT_DOSStub_302b {
  strings:
    $key_302b = { 64 43 [2] 10 5b [2] 57 59 [2] 10 48 [2] 5e 44 [2] 52 4e [2] 45 45 [2] 5e 0b [2] 63 }

  condition:
    any of them
}