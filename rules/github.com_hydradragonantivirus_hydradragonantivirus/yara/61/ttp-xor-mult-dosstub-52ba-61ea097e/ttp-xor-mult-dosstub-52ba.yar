rule TTP_XOR_MULT_DOSStub_52ba {
  strings:
    $key_52ba = { 06 d2 [2] 72 ca [2] 35 c8 [2] 72 d9 [2] 3c d5 [2] 30 df [2] 27 d4 [2] 3c 9a [2] 01 }

  condition:
    any of them
}