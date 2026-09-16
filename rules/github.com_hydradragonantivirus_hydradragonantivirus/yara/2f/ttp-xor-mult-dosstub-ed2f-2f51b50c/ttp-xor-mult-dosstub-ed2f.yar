rule TTP_XOR_MULT_DOSStub_ed2f {
  strings:
    $key_ed2f = { b9 47 [2] cd 5f [2] 8a 5d [2] cd 4c [2] 83 40 [2] 8f 4a [2] 98 41 [2] 83 0f [2] be }

  condition:
    any of them
}