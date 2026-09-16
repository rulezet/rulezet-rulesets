rule TTP_XOR_MULT_DOSStub_9f32 {
  strings:
    $key_9f32 = { cb 5a [2] bf 42 [2] f8 40 [2] bf 51 [2] f1 5d [2] fd 57 [2] ea 5c [2] f1 12 [2] cc }

  condition:
    any of them
}