rule TTP_XOR_MULT_DOSStub_fb7a {
  strings:
    $key_fb7a = { af 12 [2] db 0a [2] 9c 08 [2] db 19 [2] 95 15 [2] 99 1f [2] 8e 14 [2] 95 5a [2] a8 }

  condition:
    any of them
}