rule TTP_XOR_MULT_DOSStub_fbec {
  strings:
    $key_fbec = { af 84 [2] db 9c [2] 9c 9e [2] db 8f [2] 95 83 [2] 99 89 [2] 8e 82 [2] 95 cc [2] a8 }

  condition:
    any of them
}