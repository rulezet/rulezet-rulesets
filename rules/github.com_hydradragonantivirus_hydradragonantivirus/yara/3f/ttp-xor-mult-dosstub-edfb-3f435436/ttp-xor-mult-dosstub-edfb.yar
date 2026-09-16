rule TTP_XOR_MULT_DOSStub_edfb {
  strings:
    $key_edfb = { b9 93 [2] cd 8b [2] 8a 89 [2] cd 98 [2] 83 94 [2] 8f 9e [2] 98 95 [2] 83 db [2] be }

  condition:
    any of them
}