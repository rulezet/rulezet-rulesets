rule TTP_XOR_MULT_DOSStub_899f {
  strings:
    $key_899f = { dd f7 [2] a9 ef [2] ee ed [2] a9 fc [2] e7 f0 [2] eb fa [2] fc f1 [2] e7 bf [2] da }

  condition:
    any of them
}