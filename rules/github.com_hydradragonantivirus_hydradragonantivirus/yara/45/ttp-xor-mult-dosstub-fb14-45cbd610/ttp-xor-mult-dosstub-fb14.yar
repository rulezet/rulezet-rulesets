rule TTP_XOR_MULT_DOSStub_fb14 {
  strings:
    $key_fb14 = { af 7c [2] db 64 [2] 9c 66 [2] db 77 [2] 95 7b [2] 99 71 [2] 8e 7a [2] 95 34 [2] a8 }

  condition:
    any of them
}