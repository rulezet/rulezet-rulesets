rule TTP_XOR_MULT_DOSStub_fb1a {
  strings:
    $key_fb1a = { af 72 [2] db 6a [2] 9c 68 [2] db 79 [2] 95 75 [2] 99 7f [2] 8e 74 [2] 95 3a [2] a8 }

  condition:
    any of them
}