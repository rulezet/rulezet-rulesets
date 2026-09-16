rule TTP_XOR_MULT_DOSStub_50ba {
  strings:
    $key_50ba = { 04 d2 [2] 70 ca [2] 37 c8 [2] 70 d9 [2] 3e d5 [2] 32 df [2] 25 d4 [2] 3e 9a [2] 03 }

  condition:
    any of them
}