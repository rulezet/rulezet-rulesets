rule TTP_XOR_MULT_DOSStub_5ffd {
  strings:
    $key_5ffd = { 0b 95 [2] 7f 8d [2] 38 8f [2] 7f 9e [2] 31 92 [2] 3d 98 [2] 2a 93 [2] 31 dd [2] 0c }

  condition:
    any of them
}