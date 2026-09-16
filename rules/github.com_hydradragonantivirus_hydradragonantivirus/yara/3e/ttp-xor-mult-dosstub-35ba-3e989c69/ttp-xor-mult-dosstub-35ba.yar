rule TTP_XOR_MULT_DOSStub_35ba {
  strings:
    $key_35ba = { 61 d2 [2] 15 ca [2] 52 c8 [2] 15 d9 [2] 5b d5 [2] 57 df [2] 40 d4 [2] 5b 9a [2] 66 }

  condition:
    any of them
}