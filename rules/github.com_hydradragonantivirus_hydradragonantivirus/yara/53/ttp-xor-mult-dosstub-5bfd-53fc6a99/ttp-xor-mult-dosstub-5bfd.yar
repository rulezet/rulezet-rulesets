rule TTP_XOR_MULT_DOSStub_5bfd {
  strings:
    $key_5bfd = { 0f 95 [2] 7b 8d [2] 3c 8f [2] 7b 9e [2] 35 92 [2] 39 98 [2] 2e 93 [2] 35 dd [2] 08 }

  condition:
    any of them
}