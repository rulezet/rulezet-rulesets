rule TTP_XOR_MULT_DOSStub_ed0f {
  strings:
    $key_ed0f = { b9 67 [2] cd 7f [2] 8a 7d [2] cd 6c [2] 83 60 [2] 8f 6a [2] 98 61 [2] 83 2f [2] be }

  condition:
    any of them
}