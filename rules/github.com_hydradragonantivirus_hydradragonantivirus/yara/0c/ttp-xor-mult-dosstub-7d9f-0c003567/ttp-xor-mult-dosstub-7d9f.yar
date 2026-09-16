rule TTP_XOR_MULT_DOSStub_7d9f {
  strings:
    $key_7d9f = { 29 f7 [2] 5d ef [2] 1a ed [2] 5d fc [2] 13 f0 [2] 1f fa [2] 08 f1 [2] 13 bf [2] 2e }

  condition:
    any of them
}