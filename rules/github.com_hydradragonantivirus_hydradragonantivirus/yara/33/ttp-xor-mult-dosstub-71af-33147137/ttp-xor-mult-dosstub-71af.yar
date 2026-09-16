rule TTP_XOR_MULT_DOSStub_71af {
  strings:
    $key_71af = { 25 c7 [2] 51 df [2] 16 dd [2] 51 cc [2] 1f c0 [2] 13 ca [2] 04 c1 [2] 1f 8f [2] 22 }

  condition:
    any of them
}