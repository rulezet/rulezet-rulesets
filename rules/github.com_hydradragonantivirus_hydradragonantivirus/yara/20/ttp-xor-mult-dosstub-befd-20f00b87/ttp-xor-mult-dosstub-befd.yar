rule TTP_XOR_MULT_DOSStub_befd {
  strings:
    $key_befd = { ea 95 [2] 9e 8d [2] d9 8f [2] 9e 9e [2] d0 92 [2] dc 98 [2] cb 93 [2] d0 dd [2] ed }

  condition:
    any of them
}