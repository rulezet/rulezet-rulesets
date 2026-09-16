rule TTP_XOR_MULT_DOSStub_4cfd {
  strings:
    $key_4cfd = { 18 95 [2] 6c 8d [2] 2b 8f [2] 6c 9e [2] 22 92 [2] 2e 98 [2] 39 93 [2] 22 dd [2] 1f }

  condition:
    any of them
}