rule TTP_XOR_MULT_DOSStub_fb1c {
  strings:
    $key_fb1c = { af 74 [2] db 6c [2] 9c 6e [2] db 7f [2] 95 73 [2] 99 79 [2] 8e 72 [2] 95 3c [2] a8 }

  condition:
    any of them
}