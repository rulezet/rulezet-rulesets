rule TTP_XOR_MULT_DOSStub_44af {
  strings:
    $key_44af = { 10 c7 [2] 64 df [2] 23 dd [2] 64 cc [2] 2a c0 [2] 26 ca [2] 31 c1 [2] 2a 8f [2] 17 }

  condition:
    any of them
}