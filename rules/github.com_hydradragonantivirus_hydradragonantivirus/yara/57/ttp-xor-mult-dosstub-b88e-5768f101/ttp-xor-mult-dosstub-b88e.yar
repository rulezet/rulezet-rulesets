rule TTP_XOR_MULT_DOSStub_b88e {
  strings:
    $key_b88e = { ec e6 [2] 98 fe [2] df fc [2] 98 ed [2] d6 e1 [2] da eb [2] cd e0 [2] d6 ae [2] eb }

  condition:
    any of them
}