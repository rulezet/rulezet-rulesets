rule TTP_XOR_MULT_DOSStub_5cfd {
  strings:
    $key_5cfd = { 08 95 [2] 7c 8d [2] 3b 8f [2] 7c 9e [2] 32 92 [2] 3e 98 [2] 29 93 [2] 32 dd [2] 0f }

  condition:
    any of them
}