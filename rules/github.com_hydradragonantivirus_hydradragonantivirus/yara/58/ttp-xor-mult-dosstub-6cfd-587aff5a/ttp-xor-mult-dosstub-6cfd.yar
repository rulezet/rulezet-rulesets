rule TTP_XOR_MULT_DOSStub_6cfd {
  strings:
    $key_6cfd = { 38 95 [2] 4c 8d [2] 0b 8f [2] 4c 9e [2] 02 92 [2] 0e 98 [2] 19 93 [2] 02 dd [2] 3f }

  condition:
    any of them
}