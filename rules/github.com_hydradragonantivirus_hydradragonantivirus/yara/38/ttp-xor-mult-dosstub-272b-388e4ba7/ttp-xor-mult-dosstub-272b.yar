rule TTP_XOR_MULT_DOSStub_272b {
  strings:
    $key_272b = { 73 43 [2] 07 5b [2] 40 59 [2] 07 48 [2] 49 44 [2] 45 4e [2] 52 45 [2] 49 0b [2] 74 }

  condition:
    any of them
}