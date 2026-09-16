rule TTP_XOR_MULT_DOSStub_ad9c {
  strings:
    $key_ad9c = { f9 f4 [2] 8d ec [2] ca ee [2] 8d ff [2] c3 f3 [2] cf f9 [2] d8 f2 [2] c3 bc [2] fe }

  condition:
    any of them
}