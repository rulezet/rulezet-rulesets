rule TTP_XOR_MULT_DOSStub_fdfd {
  strings:
    $key_fdfd = { a9 95 [2] dd 8d [2] 9a 8f [2] dd 9e [2] 93 92 [2] 9f 98 [2] 88 93 [2] 93 dd [2] ae }

  condition:
    any of them
}