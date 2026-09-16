rule TTP_XOR_MULT_DOSStub_44ba {
  strings:
    $key_44ba = { 10 d2 [2] 64 ca [2] 23 c8 [2] 64 d9 [2] 2a d5 [2] 26 df [2] 31 d4 [2] 2a 9a [2] 17 }

  condition:
    any of them
}