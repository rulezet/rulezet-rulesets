rule TTP_XOR_MULT_DOSStub_b2af {
  strings:
    $key_b2af = { e6 c7 [2] 92 df [2] d5 dd [2] 92 cc [2] dc c0 [2] d0 ca [2] c7 c1 [2] dc 8f [2] e1 }

  condition:
    any of them
}