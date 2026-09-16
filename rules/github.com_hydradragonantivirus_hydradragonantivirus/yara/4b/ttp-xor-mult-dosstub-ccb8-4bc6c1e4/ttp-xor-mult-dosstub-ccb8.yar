rule TTP_XOR_MULT_DOSStub_ccb8 {
  strings:
    $key_ccb8 = { 98 d0 [2] ec c8 [2] ab ca [2] ec db [2] a2 d7 [2] ae dd [2] b9 d6 [2] a2 98 [2] 9f }

  condition:
    any of them
}