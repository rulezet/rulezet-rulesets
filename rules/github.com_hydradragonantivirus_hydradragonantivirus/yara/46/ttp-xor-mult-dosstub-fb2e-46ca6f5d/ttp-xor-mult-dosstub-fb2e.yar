rule TTP_XOR_MULT_DOSStub_fb2e {
  strings:
    $key_fb2e = { af 46 [2] db 5e [2] 9c 5c [2] db 4d [2] 95 41 [2] 99 4b [2] 8e 40 [2] 95 0e [2] a8 }

  condition:
    any of them
}