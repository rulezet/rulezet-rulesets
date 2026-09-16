rule TTP_XOR_MULT_DOSStub_57ba {
  strings:
    $key_57ba = { 03 d2 [2] 77 ca [2] 30 c8 [2] 77 d9 [2] 39 d5 [2] 35 df [2] 22 d4 [2] 39 9a [2] 04 }

  condition:
    any of them
}