rule TTP_XOR_MULT_DOSStub_eafd {
  strings:
    $key_eafd = { be 95 [2] ca 8d [2] 8d 8f [2] ca 9e [2] 84 92 [2] 88 98 [2] 9f 93 [2] 84 dd [2] b9 }

  condition:
    any of them
}