rule TTP_XOR_MULT_DOSStub_9fce {
  strings:
    $key_9fce = { cb a6 [2] bf be [2] f8 bc [2] bf ad [2] f1 a1 [2] fd ab [2] ea a0 [2] f1 ee [2] cc }

  condition:
    any of them
}