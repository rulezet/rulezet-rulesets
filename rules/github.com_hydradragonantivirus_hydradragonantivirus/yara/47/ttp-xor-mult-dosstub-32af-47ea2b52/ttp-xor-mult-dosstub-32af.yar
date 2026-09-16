rule TTP_XOR_MULT_DOSStub_32af {
  strings:
    $key_32af = { 66 c7 [2] 12 df [2] 55 dd [2] 12 cc [2] 5c c0 [2] 50 ca [2] 47 c1 [2] 5c 8f [2] 61 }

  condition:
    any of them
}