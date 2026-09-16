rule TTP_XOR_MULT_DOSStub_fb3c {
  strings:
    $key_fb3c = { af 54 [2] db 4c [2] 9c 4e [2] db 5f [2] 95 53 [2] 99 59 [2] 8e 52 [2] 95 1c [2] a8 }

  condition:
    any of them
}