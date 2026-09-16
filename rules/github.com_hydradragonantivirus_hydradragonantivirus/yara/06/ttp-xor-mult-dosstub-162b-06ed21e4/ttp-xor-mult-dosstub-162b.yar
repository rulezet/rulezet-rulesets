rule TTP_XOR_MULT_DOSStub_162b {
  strings:
    $key_162b = { 42 43 [2] 36 5b [2] 71 59 [2] 36 48 [2] 78 44 [2] 74 4e [2] 63 45 [2] 78 0b [2] 45 }

  condition:
    any of them
}