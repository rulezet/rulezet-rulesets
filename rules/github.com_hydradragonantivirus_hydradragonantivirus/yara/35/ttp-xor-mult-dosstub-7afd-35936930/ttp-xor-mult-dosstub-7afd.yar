rule TTP_XOR_MULT_DOSStub_7afd {
  strings:
    $key_7afd = { 2e 95 [2] 5a 8d [2] 1d 8f [2] 5a 9e [2] 14 92 [2] 18 98 [2] 0f 93 [2] 14 dd [2] 29 }

  condition:
    any of them
}