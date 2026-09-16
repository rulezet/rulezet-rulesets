rule TTP_XOR_MULT_DOSStub_07af {
  strings:
    $key_07af = { 53 c7 [2] 27 df [2] 60 dd [2] 27 cc [2] 69 c0 [2] 65 ca [2] 72 c1 [2] 69 8f [2] 54 }

  condition:
    any of them
}