rule TTP_XOR_MULT_DOSStub_f2af {
  strings:
    $key_f2af = { a6 c7 [2] d2 df [2] 95 dd [2] d2 cc [2] 9c c0 [2] 90 ca [2] 87 c1 [2] 9c 8f [2] a1 }

  condition:
    any of them
}