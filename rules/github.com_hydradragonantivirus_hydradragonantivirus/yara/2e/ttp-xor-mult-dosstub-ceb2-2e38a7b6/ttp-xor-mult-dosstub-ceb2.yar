rule TTP_XOR_MULT_DOSStub_ceb2 {
  strings:
    $key_ceb2 = { 9a da [2] ee c2 [2] a9 c0 [2] ee d1 [2] a0 dd [2] ac d7 [2] bb dc [2] a0 92 [2] 9d }

  condition:
    any of them
}