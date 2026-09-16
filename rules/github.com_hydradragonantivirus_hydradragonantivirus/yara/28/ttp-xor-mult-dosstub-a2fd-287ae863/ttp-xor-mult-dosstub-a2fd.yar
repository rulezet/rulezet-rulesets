rule TTP_XOR_MULT_DOSStub_a2fd {
  strings:
    $key_a2fd = { f6 95 [2] 82 8d [2] c5 8f [2] 82 9e [2] cc 92 [2] c0 98 [2] d7 93 [2] cc dd [2] f1 }

  condition:
    any of them
}