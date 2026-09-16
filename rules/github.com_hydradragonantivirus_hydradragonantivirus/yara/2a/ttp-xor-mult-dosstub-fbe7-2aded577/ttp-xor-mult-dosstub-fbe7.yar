rule TTP_XOR_MULT_DOSStub_fbe7 {
  strings:
    $key_fbe7 = { af 8f [2] db 97 [2] 9c 95 [2] db 84 [2] 95 88 [2] 99 82 [2] 8e 89 [2] 95 c7 [2] a8 }

  condition:
    any of them
}