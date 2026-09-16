rule TTP_XOR_MULT_DOSStub_fbf2 {
  strings:
    $key_fbf2 = { af 9a [2] db 82 [2] 9c 80 [2] db 91 [2] 95 9d [2] 99 97 [2] 8e 9c [2] 95 d2 [2] a8 }

  condition:
    any of them
}