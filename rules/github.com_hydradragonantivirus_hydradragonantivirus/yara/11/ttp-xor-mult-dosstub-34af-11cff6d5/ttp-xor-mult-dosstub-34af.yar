rule TTP_XOR_MULT_DOSStub_34af {
  strings:
    $key_34af = { 60 c7 [2] 14 df [2] 53 dd [2] 14 cc [2] 5a c0 [2] 56 ca [2] 41 c1 [2] 5a 8f [2] 67 }

  condition:
    any of them
}