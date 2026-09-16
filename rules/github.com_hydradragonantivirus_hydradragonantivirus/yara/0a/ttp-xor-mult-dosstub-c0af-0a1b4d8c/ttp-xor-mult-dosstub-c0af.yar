rule TTP_XOR_MULT_DOSStub_c0af {
  strings:
    $key_c0af = { 94 c7 [2] e0 df [2] a7 dd [2] e0 cc [2] ae c0 [2] a2 ca [2] b5 c1 [2] ae 8f [2] 93 }

  condition:
    any of them
}