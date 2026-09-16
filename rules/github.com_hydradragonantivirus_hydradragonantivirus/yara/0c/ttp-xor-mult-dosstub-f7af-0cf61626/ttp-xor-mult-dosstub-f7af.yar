rule TTP_XOR_MULT_DOSStub_f7af {
  strings:
    $key_f7af = { a3 c7 [2] d7 df [2] 90 dd [2] d7 cc [2] 99 c0 [2] 95 ca [2] 82 c1 [2] 99 8f [2] a4 }

  condition:
    any of them
}