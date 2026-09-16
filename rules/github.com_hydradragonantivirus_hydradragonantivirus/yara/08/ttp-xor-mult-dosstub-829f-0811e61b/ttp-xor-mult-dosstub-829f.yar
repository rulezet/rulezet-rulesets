rule TTP_XOR_MULT_DOSStub_829f {
  strings:
    $key_829f = { d6 f7 [2] a2 ef [2] e5 ed [2] a2 fc [2] ec f0 [2] e0 fa [2] f7 f1 [2] ec bf [2] d1 }

  condition:
    any of them
}