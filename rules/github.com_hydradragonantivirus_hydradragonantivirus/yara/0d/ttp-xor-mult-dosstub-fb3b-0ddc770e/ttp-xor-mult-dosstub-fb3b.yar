rule TTP_XOR_MULT_DOSStub_fb3b {
  strings:
    $key_fb3b = { af 53 [2] db 4b [2] 9c 49 [2] db 58 [2] 95 54 [2] 99 5e [2] 8e 55 [2] 95 1b [2] a8 }

  condition:
    any of them
}