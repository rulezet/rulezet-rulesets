rule TTP_XOR_MULT_DOSStub_fb7d {
  strings:
    $key_fb7d = { af 15 [2] db 0d [2] 9c 0f [2] db 1e [2] 95 12 [2] 99 18 [2] 8e 13 [2] 95 5d [2] a8 }

  condition:
    any of them
}