rule TTP_XOR_MULT_DOSStub_6ffd {
  strings:
    $key_6ffd = { 3b 95 [2] 4f 8d [2] 08 8f [2] 4f 9e [2] 01 92 [2] 0d 98 [2] 1a 93 [2] 01 dd [2] 3c }

  condition:
    any of them
}