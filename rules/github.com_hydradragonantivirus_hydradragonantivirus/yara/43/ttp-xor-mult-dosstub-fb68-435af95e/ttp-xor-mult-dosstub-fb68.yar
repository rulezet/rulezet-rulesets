rule TTP_XOR_MULT_DOSStub_fb68 {
  strings:
    $key_fb68 = { af 00 [2] db 18 [2] 9c 1a [2] db 0b [2] 95 07 [2] 99 0d [2] 8e 06 [2] 95 48 [2] a8 }

  condition:
    any of them
}