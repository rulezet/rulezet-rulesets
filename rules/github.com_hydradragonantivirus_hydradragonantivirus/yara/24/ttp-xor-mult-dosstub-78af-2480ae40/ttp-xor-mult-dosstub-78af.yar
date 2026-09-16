rule TTP_XOR_MULT_DOSStub_78af {
  strings:
    $key_78af = { 2c c7 [2] 58 df [2] 1f dd [2] 58 cc [2] 16 c0 [2] 1a ca [2] 0d c1 [2] 16 8f [2] 2b }

  condition:
    any of them
}