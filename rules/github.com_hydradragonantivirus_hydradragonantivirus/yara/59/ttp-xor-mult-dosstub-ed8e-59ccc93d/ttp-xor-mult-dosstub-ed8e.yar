rule TTP_XOR_MULT_DOSStub_ed8e {
  strings:
    $key_ed8e = { b9 e6 [2] cd fe [2] 8a fc [2] cd ed [2] 83 e1 [2] 8f eb [2] 98 e0 [2] 83 ae [2] be }

  condition:
    any of them
}