rule TTP_XOR_MULT_DOSStub_fbe6 {
  strings:
    $key_fbe6 = { af 8e [2] db 96 [2] 9c 94 [2] db 85 [2] 95 89 [2] 99 83 [2] 8e 88 [2] 95 c6 [2] a8 }

  condition:
    any of them
}