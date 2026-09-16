rule TTP_XOR_MULT_DOSStub_8fce {
  strings:
    $key_8fce = { db a6 [2] af be [2] e8 bc [2] af ad [2] e1 a1 [2] ed ab [2] fa a0 [2] e1 ee [2] dc }

  condition:
    any of them
}