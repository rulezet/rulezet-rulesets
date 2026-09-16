rule TTP_XOR_MULT_DOSStub_edbf {
  strings:
    $key_edbf = { b9 d7 [2] cd cf [2] 8a cd [2] cd dc [2] 83 d0 [2] 8f da [2] 98 d1 [2] 83 9f [2] be }

  condition:
    any of them
}