rule TTP_XOR_MULT_DOSStub_edad {
  strings:
    $key_edad = { b9 c5 [2] cd dd [2] 8a df [2] cd ce [2] 83 c2 [2] 8f c8 [2] 98 c3 [2] 83 8d [2] be }

  condition:
    any of them
}