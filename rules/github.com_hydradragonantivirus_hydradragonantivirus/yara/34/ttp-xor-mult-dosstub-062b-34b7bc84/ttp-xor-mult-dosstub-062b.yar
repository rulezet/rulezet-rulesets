rule TTP_XOR_MULT_DOSStub_062b {
  strings:
    $key_062b = { 52 43 [2] 26 5b [2] 61 59 [2] 26 48 [2] 68 44 [2] 64 4e [2] 73 45 [2] 68 0b [2] 55 }

  condition:
    any of them
}