rule TTP_XOR_MULT_DOSStub_fb2a {
  strings:
    $key_fb2a = { af 42 [2] db 5a [2] 9c 58 [2] db 49 [2] 95 45 [2] 99 4f [2] 8e 44 [2] 95 0a [2] a8 }

  condition:
    any of them
}