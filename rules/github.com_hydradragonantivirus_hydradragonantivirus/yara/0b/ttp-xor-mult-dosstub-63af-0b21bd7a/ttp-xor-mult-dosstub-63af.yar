rule TTP_XOR_MULT_DOSStub_63af {
  strings:
    $key_63af = { 37 c7 [2] 43 df [2] 04 dd [2] 43 cc [2] 0d c0 [2] 01 ca [2] 16 c1 [2] 0d 8f [2] 30 }

  condition:
    any of them
}