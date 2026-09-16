rule TTP_XOR_MULT_DOSStub_ceb8 {
  strings:
    $key_ceb8 = { 9a d0 [2] ee c8 [2] a9 ca [2] ee db [2] a0 d7 [2] ac dd [2] bb d6 [2] a0 98 [2] 9d }

  condition:
    any of them
}