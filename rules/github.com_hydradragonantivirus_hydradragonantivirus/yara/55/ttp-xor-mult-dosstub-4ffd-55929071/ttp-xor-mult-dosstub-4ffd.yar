rule TTP_XOR_MULT_DOSStub_4ffd {
  strings:
    $key_4ffd = { 1b 95 [2] 6f 8d [2] 28 8f [2] 6f 9e [2] 21 92 [2] 2d 98 [2] 3a 93 [2] 21 dd [2] 1c }

  condition:
    any of them
}