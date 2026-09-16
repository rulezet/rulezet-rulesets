rule TTP_XOR_MULT_DOSStub_fbfd {
  strings:
    $key_fbfd = { af 95 [2] db 8d [2] 9c 8f [2] db 9e [2] 95 92 [2] 99 98 [2] 8e 93 [2] 95 dd [2] a8 }

  condition:
    any of them
}