rule TTP_XOR_MULT_DOSStub_6120 {
  strings:
    $key_6120 = { 35 48 [2] 41 50 [2] 06 52 [2] 41 43 [2] 0f 4f [2] 03 45 [2] 14 4e [2] 0f 00 [2] 32 }

  condition:
    any of them
}