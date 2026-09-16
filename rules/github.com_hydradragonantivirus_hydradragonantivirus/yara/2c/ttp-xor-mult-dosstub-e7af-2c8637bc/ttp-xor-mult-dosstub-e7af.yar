rule TTP_XOR_MULT_DOSStub_e7af {
  strings:
    $key_e7af = { b3 c7 [2] c7 df [2] 80 dd [2] c7 cc [2] 89 c0 [2] 85 ca [2] 92 c1 [2] 89 8f [2] b4 }

  condition:
    any of them
}