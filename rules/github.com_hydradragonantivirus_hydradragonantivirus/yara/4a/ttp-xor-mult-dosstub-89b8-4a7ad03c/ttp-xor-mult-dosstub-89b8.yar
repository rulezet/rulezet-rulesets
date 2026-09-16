rule TTP_XOR_MULT_DOSStub_89b8 {
  strings:
    $key_89b8 = { dd d0 [2] a9 c8 [2] ee ca [2] a9 db [2] e7 d7 [2] eb dd [2] fc d6 [2] e7 98 [2] da }

  condition:
    any of them
}