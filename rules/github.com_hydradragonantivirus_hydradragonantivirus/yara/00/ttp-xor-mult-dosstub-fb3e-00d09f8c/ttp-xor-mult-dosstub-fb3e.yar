rule TTP_XOR_MULT_DOSStub_fb3e {
  strings:
    $key_fb3e = { af 56 [2] db 4e [2] 9c 4c [2] db 5d [2] 95 51 [2] 99 5b [2] 8e 50 [2] 95 1e [2] a8 }

  condition:
    any of them
}