rule TTP_XOR_MULT_DOSStub_3db8 {
  strings:
    $key_3db8 = { 69 d0 [2] 1d c8 [2] 5a ca [2] 1d db [2] 53 d7 [2] 5f dd [2] 48 d6 [2] 53 98 [2] 6e }

  condition:
    any of them
}