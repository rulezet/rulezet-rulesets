rule TTP_XOR_MULT_DOSStub_9471 {
  strings:
    $key_9471 = { c0 19 [2] b4 01 [2] f3 03 [2] b4 12 [2] fa 1e [2] f6 14 [2] e1 1f [2] fa 51 [2] c7 }

  condition:
    any of them
}