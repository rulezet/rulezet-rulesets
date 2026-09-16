rule TTP_XOR_MULT_DOSStub_9883 {
  strings:
    $key_9883 = { cc eb [2] b8 f3 [2] ff f1 [2] b8 e0 [2] f6 ec [2] fa e6 [2] ed ed [2] f6 a3 [2] cb }

  condition:
    any of them
}