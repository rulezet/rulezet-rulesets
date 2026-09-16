rule TTP_XOR_MULT_DOSStub_fbea {
  strings:
    $key_fbea = { af 82 [2] db 9a [2] 9c 98 [2] db 89 [2] 95 85 [2] 99 8f [2] 8e 84 [2] 95 ca [2] a8 }

  condition:
    any of them
}