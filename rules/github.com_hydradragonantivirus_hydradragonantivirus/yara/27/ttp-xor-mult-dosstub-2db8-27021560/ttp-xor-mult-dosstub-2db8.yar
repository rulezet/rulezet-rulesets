rule TTP_XOR_MULT_DOSStub_2db8 {
  strings:
    $key_2db8 = { 79 d0 [2] 0d c8 [2] 4a ca [2] 0d db [2] 43 d7 [2] 4f dd [2] 58 d6 [2] 43 98 [2] 7e }

  condition:
    any of them
}