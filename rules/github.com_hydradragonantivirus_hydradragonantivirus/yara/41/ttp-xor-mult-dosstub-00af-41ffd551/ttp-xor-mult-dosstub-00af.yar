rule TTP_XOR_MULT_DOSStub_00af {
  strings:
    $key_00af = { 54 c7 [2] 20 df [2] 67 dd [2] 20 cc [2] 6e c0 [2] 62 ca [2] 75 c1 [2] 6e 8f [2] 53 }

  condition:
    any of them
}