rule TTP_XOR_MULT_DOSStub_ed8f {
  strings:
    $key_ed8f = { b9 e7 [2] cd ff [2] 8a fd [2] cd ec [2] 83 e0 [2] 8f ea [2] 98 e1 [2] 83 af [2] be }

  condition:
    any of them
}