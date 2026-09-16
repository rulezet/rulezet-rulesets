rule TTP_XOR_MULT_DOSStub_fb7b {
  strings:
    $key_fb7b = { af 13 [2] db 0b [2] 9c 09 [2] db 18 [2] 95 14 [2] 99 1e [2] 8e 15 [2] 95 5b [2] a8 }

  condition:
    any of them
}