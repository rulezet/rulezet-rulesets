rule TTP_XOR_MULT_DOSStub_4db8 {
  strings:
    $key_4db8 = { 19 d0 [2] 6d c8 [2] 2a ca [2] 6d db [2] 23 d7 [2] 2f dd [2] 38 d6 [2] 23 98 [2] 1e }

  condition:
    any of them
}