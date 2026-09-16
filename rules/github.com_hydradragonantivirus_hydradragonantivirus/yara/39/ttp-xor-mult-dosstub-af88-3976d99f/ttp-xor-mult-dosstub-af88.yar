rule TTP_XOR_MULT_DOSStub_af88 {
  strings:
    $key_af88 = { fb e0 [2] 8f f8 [2] c8 fa [2] 8f eb [2] c1 e7 [2] cd ed [2] da e6 [2] c1 a8 [2] fc }

  condition:
    any of them
}