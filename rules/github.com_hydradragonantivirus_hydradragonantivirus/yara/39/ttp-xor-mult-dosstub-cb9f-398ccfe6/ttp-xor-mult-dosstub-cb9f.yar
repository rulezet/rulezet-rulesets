rule TTP_XOR_MULT_DOSStub_cb9f {
  strings:
    $key_cb9f = { 9f f7 [2] eb ef [2] ac ed [2] eb fc [2] a5 f0 [2] a9 fa [2] be f1 [2] a5 bf [2] 98 }

  condition:
    any of them
}