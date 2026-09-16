rule TTP_XOR_MULT_DOSStub_ad9f {
  strings:
    $key_ad9f = { f9 f7 [2] 8d ef [2] ca ed [2] 8d fc [2] c3 f0 [2] cf fa [2] d8 f1 [2] c3 bf [2] fe }

  condition:
    any of them
}