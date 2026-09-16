rule TTP_XOR_MULT_DOSStub_fb6f {
  strings:
    $key_fb6f = { af 07 [2] db 1f [2] 9c 1d [2] db 0c [2] 95 00 [2] 99 0a [2] 8e 01 [2] 95 4f [2] a8 }

  condition:
    any of them
}