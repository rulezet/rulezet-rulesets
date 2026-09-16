rule TTP_XOR_MULT_DOSStub_bbfd {
  strings:
    $key_bbfd = { ef 95 [2] 9b 8d [2] dc 8f [2] 9b 9e [2] d5 92 [2] d9 98 [2] ce 93 [2] d5 dd [2] e8 }

  condition:
    any of them
}