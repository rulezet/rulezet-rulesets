rule TTP_XOR_MULT_DOSStub_f2ba {
  strings:
    $key_f2ba = { a6 d2 [2] d2 ca [2] 95 c8 [2] d2 d9 [2] 9c d5 [2] 90 df [2] 87 d4 [2] 9c 9a [2] a1 }

  condition:
    any of them
}