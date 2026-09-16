rule TTP_XOR_MULT_DOSStub_cece {
  strings:
    $key_cece = { 9a a6 [2] ee be [2] a9 bc [2] ee ad [2] a0 a1 [2] ac ab [2] bb a0 [2] a0 ee [2] 9d }

  condition:
    any of them
}