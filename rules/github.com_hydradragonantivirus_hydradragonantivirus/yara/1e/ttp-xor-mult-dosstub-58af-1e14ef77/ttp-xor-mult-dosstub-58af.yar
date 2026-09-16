rule TTP_XOR_MULT_DOSStub_58af {
  strings:
    $key_58af = { 0c c7 [2] 78 df [2] 3f dd [2] 78 cc [2] 36 c0 [2] 3a ca [2] 2d c1 [2] 36 8f [2] 0b }

  condition:
    any of them
}