rule TTP_XOR_MULT_DOSStub_7ffd {
  strings:
    $key_7ffd = { 2b 95 [2] 5f 8d [2] 18 8f [2] 5f 9e [2] 11 92 [2] 1d 98 [2] 0a 93 [2] 11 dd [2] 2c }

  condition:
    any of them
}