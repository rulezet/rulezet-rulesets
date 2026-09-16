rule TTP_XOR_MULT_DOSStub_fb2c {
  strings:
    $key_fb2c = { af 44 [2] db 5c [2] 9c 5e [2] db 4f [2] 95 43 [2] 99 49 [2] 8e 42 [2] 95 0c [2] a8 }

  condition:
    any of them
}