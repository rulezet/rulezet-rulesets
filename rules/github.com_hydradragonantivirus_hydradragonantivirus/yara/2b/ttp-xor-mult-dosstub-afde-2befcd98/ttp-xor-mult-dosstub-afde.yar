rule TTP_XOR_MULT_DOSStub_afde {
  strings:
    $key_afde = { fb b6 [2] 8f ae [2] c8 ac [2] 8f bd [2] c1 b1 [2] cd bb [2] da b0 [2] c1 fe [2] fc }

  condition:
    any of them
}