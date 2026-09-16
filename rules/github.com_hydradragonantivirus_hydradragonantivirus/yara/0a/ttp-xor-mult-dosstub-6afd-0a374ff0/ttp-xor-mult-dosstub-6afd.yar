rule TTP_XOR_MULT_DOSStub_6afd {
  strings:
    $key_6afd = { 3e 95 [2] 4a 8d [2] 0d 8f [2] 4a 9e [2] 04 92 [2] 08 98 [2] 1f 93 [2] 04 dd [2] 39 }

  condition:
    any of them
}