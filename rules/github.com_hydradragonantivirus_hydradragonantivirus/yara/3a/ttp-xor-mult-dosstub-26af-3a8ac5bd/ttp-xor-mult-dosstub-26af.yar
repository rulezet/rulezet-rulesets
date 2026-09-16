rule TTP_XOR_MULT_DOSStub_26af {
  strings:
    $key_26af = { 72 c7 [2] 06 df [2] 41 dd [2] 06 cc [2] 48 c0 [2] 44 ca [2] 53 c1 [2] 48 8f [2] 75 }

  condition:
    any of them
}