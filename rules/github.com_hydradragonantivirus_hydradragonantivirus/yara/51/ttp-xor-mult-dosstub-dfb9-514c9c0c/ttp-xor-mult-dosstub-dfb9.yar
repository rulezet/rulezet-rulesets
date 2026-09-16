rule TTP_XOR_MULT_DOSStub_dfb9 {
  strings:
    $key_dfb9 = { 8b d1 [2] ff c9 [2] b8 cb [2] ff da [2] b1 d6 [2] bd dc [2] aa d7 [2] b1 99 [2] 8c }

  condition:
    any of them
}