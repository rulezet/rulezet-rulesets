rule TTP_XOR_MULT_DOSStub_fb40 {
  strings:
    $key_fb40 = { af 28 [2] db 30 [2] 9c 32 [2] db 23 [2] 95 2f [2] 99 25 [2] 8e 2e [2] 95 60 [2] a8 }

  condition:
    any of them
}