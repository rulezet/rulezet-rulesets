rule TTP_XOR_MULT_DOSStub_56ba {
  strings:
    $key_56ba = { 02 d2 [2] 76 ca [2] 31 c8 [2] 76 d9 [2] 38 d5 [2] 34 df [2] 23 d4 [2] 38 9a [2] 05 }

  condition:
    any of them
}