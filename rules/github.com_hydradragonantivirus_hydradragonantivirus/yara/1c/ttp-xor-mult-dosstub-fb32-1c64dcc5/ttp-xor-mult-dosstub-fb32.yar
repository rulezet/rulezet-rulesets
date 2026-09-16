rule TTP_XOR_MULT_DOSStub_fb32 {
  strings:
    $key_fb32 = { af 5a [2] db 42 [2] 9c 40 [2] db 51 [2] 95 5d [2] 99 57 [2] 8e 5c [2] 95 12 [2] a8 }

  condition:
    any of them
}