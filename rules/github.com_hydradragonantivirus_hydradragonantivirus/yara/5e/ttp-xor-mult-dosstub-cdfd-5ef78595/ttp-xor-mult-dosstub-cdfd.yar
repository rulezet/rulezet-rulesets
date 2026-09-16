rule TTP_XOR_MULT_DOSStub_cdfd {
  strings:
    $key_cdfd = { 99 95 [2] ed 8d [2] aa 8f [2] ed 9e [2] a3 92 [2] af 98 [2] b8 93 [2] a3 dd [2] 9e }

  condition:
    any of them
}