rule TTP_XOR_MULT_DOSStub_dad0 {
  strings:
    $key_dad0 = { 8e b8 [2] fa a0 [2] bd a2 [2] fa b3 [2] b4 bf [2] b8 b5 [2] af be [2] b4 f0 [2] 89 }

  condition:
    any of them
}