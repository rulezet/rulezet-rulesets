rule TTP_XOR_MULT_DOSStub_28af {
  strings:
    $key_28af = { 7c c7 [2] 08 df [2] 4f dd [2] 08 cc [2] 46 c0 [2] 4a ca [2] 5d c1 [2] 46 8f [2] 7b }

  condition:
    any of them
}