rule TTP_XOR_MULT_DOSStub_fb6b {
  strings:
    $key_fb6b = { af 03 [2] db 1b [2] 9c 19 [2] db 08 [2] 95 04 [2] 99 0e [2] 8e 05 [2] 95 4b [2] a8 }

  condition:
    any of them
}