rule TTP_XOR_MULT_DOSStub_c299 {
  strings:
    $key_c299 = { 96 f1 [2] e2 e9 [2] a5 eb [2] e2 fa [2] ac f6 [2] a0 fc [2] b7 f7 [2] ac b9 [2] 91 }

  condition:
    any of them
}