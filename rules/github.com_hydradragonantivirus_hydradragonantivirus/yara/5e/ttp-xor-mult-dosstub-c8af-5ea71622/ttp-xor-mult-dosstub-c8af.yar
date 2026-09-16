rule TTP_XOR_MULT_DOSStub_c8af {
  strings:
    $key_c8af = { 9c c7 [2] e8 df [2] af dd [2] e8 cc [2] a6 c0 [2] aa ca [2] bd c1 [2] a6 8f [2] 9b }

  condition:
    any of them
}