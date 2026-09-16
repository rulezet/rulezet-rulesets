rule TTP_XOR_MULT_DOSStub_fb74 {
  strings:
    $key_fb74 = { af 1c [2] db 04 [2] 9c 06 [2] db 17 [2] 95 1b [2] 99 11 [2] 8e 1a [2] 95 54 [2] a8 }

  condition:
    any of them
}