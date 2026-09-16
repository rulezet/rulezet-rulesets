rule TTP_XOR_MULT_DOSStub_fb1e {
  strings:
    $key_fb1e = { af 76 [2] db 6e [2] 9c 6c [2] db 7d [2] 95 71 [2] 99 7b [2] 8e 70 [2] 95 3e [2] a8 }

  condition:
    any of them
}