rule TTP_XOR_MULT_DOSStub_26ba {
  strings:
    $key_26ba = { 72 d2 [2] 06 ca [2] 41 c8 [2] 06 d9 [2] 48 d5 [2] 44 df [2] 53 d4 [2] 48 9a [2] 75 }

  condition:
    any of them
}