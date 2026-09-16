rule TTP_XOR_MULT_DOSStub_61ba {
  strings:
    $key_61ba = { 35 d2 [2] 41 ca [2] 06 c8 [2] 41 d9 [2] 0f d5 [2] 03 df [2] 14 d4 [2] 0f 9a [2] 32 }

  condition:
    any of them
}