rule TTP_XOR_MULT_DOSStub_b29f {
  strings:
    $key_b29f = { e6 f7 [2] 92 ef [2] d5 ed [2] 92 fc [2] dc f0 [2] d0 fa [2] c7 f1 [2] dc bf [2] e1 }

  condition:
    any of them
}