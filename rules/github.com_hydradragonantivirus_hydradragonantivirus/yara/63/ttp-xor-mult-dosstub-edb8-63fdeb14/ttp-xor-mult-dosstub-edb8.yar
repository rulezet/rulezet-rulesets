rule TTP_XOR_MULT_DOSStub_edb8 {
  strings:
    $key_edb8 = { b9 d0 [2] cd c8 [2] 8a ca [2] cd db [2] 83 d7 [2] 8f dd [2] 98 d6 [2] 83 98 [2] be }

  condition:
    any of them
}