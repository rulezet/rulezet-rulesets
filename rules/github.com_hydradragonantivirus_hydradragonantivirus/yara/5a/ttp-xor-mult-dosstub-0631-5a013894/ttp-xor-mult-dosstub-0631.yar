rule TTP_XOR_MULT_DOSStub_0631 {
  strings:
    $key_0631 = { 52 59 [2] 26 41 [2] 61 43 [2] 26 52 [2] 68 5e [2] 64 54 [2] 73 5f [2] 68 11 [2] 55 }

  condition:
    any of them
}