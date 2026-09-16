rule TTP_XOR_MULT_DOSStub_fb65 {
  strings:
    $key_fb65 = { af 0d [2] db 15 [2] 9c 17 [2] db 06 [2] 95 0a [2] 99 00 [2] 8e 0b [2] 95 45 [2] a8 }

  condition:
    any of them
}