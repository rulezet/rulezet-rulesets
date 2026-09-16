rule TTP_XOR_MULT_DOSStub_cd8e {
  strings:
    $key_cd8e = { 99 e6 [2] ed fe [2] aa fc [2] ed ed [2] a3 e1 [2] af eb [2] b8 e0 [2] a3 ae [2] 9e }

  condition:
    any of them
}