rule TTP_XOR_MULT_DOSStub_fb62 {
  strings:
    $key_fb62 = { af 0a [2] db 12 [2] 9c 10 [2] db 01 [2] 95 0d [2] 99 07 [2] 8e 0c [2] 95 42 [2] a8 }

  condition:
    any of them
}