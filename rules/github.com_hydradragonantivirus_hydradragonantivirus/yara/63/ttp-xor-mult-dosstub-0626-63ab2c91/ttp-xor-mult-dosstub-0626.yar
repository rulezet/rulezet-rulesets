rule TTP_XOR_MULT_DOSStub_0626 {
  strings:
    $key_0626 = { 52 4e [2] 26 56 [2] 61 54 [2] 26 45 [2] 68 49 [2] 64 43 [2] 73 48 [2] 68 06 [2] 55 }

  condition:
    any of them
}