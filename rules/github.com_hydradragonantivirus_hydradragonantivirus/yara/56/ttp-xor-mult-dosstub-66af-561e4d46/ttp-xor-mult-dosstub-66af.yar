rule TTP_XOR_MULT_DOSStub_66af {
  strings:
    $key_66af = { 32 c7 [2] 46 df [2] 01 dd [2] 46 cc [2] 08 c0 [2] 04 ca [2] 13 c1 [2] 08 8f [2] 35 }

  condition:
    any of them
}