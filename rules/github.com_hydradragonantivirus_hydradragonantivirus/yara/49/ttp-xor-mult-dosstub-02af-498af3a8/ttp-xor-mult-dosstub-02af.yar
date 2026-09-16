rule TTP_XOR_MULT_DOSStub_02af {
  strings:
    $key_02af = { 56 c7 [2] 22 df [2] 65 dd [2] 22 cc [2] 6c c0 [2] 60 ca [2] 77 c1 [2] 6c 8f [2] 51 }

  condition:
    any of them
}