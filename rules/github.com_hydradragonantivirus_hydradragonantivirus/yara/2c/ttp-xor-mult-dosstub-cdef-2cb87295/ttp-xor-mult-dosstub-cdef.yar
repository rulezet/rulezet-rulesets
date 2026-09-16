rule TTP_XOR_MULT_DOSStub_cdef {
  strings:
    $key_cdef = { 99 87 [2] ed 9f [2] aa 9d [2] ed 8c [2] a3 80 [2] af 8a [2] b8 81 [2] a3 cf [2] 9e }

  condition:
    any of them
}