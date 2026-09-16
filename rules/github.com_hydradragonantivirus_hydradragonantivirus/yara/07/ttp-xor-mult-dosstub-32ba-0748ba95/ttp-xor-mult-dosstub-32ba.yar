rule TTP_XOR_MULT_DOSStub_32ba {
  strings:
    $key_32ba = { 66 d2 [2] 12 ca [2] 55 c8 [2] 12 d9 [2] 5c d5 [2] 50 df [2] 47 d4 [2] 5c 9a [2] 61 }

  condition:
    any of them
}