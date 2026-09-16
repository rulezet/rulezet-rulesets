rule TTP_XOR_MULT_DOSStub_d0ef {
  strings:
    $key_d0ef = { 84 87 [2] f0 9f [2] b7 9d [2] f0 8c [2] be 80 [2] b2 8a [2] a5 81 [2] be cf [2] 83 }

  condition:
    any of them
}