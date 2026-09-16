rule TTP_XOR_MULT_DOSStub_11af {
  strings:
    $key_11af = { 45 c7 [2] 31 df [2] 76 dd [2] 31 cc [2] 7f c0 [2] 73 ca [2] 64 c1 [2] 7f 8f [2] 42 }

  condition:
    any of them
}