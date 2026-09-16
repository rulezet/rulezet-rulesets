rule TTP_XOR_MULT_DOSStub_fb64 {
  strings:
    $key_fb64 = { af 0c [2] db 14 [2] 9c 16 [2] db 07 [2] 95 0b [2] 99 01 [2] 8e 0a [2] 95 44 [2] a8 }

  condition:
    any of them
}