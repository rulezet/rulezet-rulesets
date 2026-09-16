rule TTP_XOR_MULT_DOSStub_08af {
  strings:
    $key_08af = { 5c c7 [2] 28 df [2] 6f dd [2] 28 cc [2] 66 c0 [2] 6a ca [2] 7d c1 [2] 66 8f [2] 5b }

  condition:
    any of them
}