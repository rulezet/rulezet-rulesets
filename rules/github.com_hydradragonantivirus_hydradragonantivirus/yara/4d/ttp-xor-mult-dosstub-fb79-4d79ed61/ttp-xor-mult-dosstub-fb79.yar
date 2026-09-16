rule TTP_XOR_MULT_DOSStub_fb79 {
  strings:
    $key_fb79 = { af 11 [2] db 09 [2] 9c 0b [2] db 1a [2] 95 16 [2] 99 1c [2] 8e 17 [2] 95 59 [2] a8 }

  condition:
    any of them
}