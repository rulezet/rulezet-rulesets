rule TTP_XOR_MULT_DOSStub_fb5f {
  strings:
    $key_fb5f = { af 37 [2] db 2f [2] 9c 2d [2] db 3c [2] 95 30 [2] 99 3a [2] 8e 31 [2] 95 7f [2] a8 }

  condition:
    any of them
}