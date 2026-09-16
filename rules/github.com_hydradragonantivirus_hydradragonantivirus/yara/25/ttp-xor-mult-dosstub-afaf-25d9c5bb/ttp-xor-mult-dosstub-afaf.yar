rule TTP_XOR_MULT_DOSStub_afaf {
  strings:
    $key_afaf = { fb c7 [2] 8f df [2] c8 dd [2] 8f cc [2] c1 c0 [2] cd ca [2] da c1 [2] c1 8f [2] fc }

  condition:
    any of them
}