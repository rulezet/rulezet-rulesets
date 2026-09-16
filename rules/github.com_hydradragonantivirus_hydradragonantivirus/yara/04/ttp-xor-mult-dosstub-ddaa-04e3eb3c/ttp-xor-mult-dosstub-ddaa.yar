rule TTP_XOR_MULT_DOSStub_ddaa {
  strings:
    $key_ddaa = { 89 c2 [2] fd da [2] ba d8 [2] fd c9 [2] b3 c5 [2] bf cf [2] a8 c4 [2] b3 8a [2] 8e }

  condition:
    any of them
}