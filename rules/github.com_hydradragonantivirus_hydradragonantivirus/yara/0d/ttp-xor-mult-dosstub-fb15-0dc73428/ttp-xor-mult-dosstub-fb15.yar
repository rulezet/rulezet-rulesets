rule TTP_XOR_MULT_DOSStub_fb15 {
  strings:
    $key_fb15 = { af 7d [2] db 65 [2] 9c 67 [2] db 76 [2] 95 7a [2] 99 70 [2] 8e 7b [2] 95 35 [2] a8 }

  condition:
    any of them
}