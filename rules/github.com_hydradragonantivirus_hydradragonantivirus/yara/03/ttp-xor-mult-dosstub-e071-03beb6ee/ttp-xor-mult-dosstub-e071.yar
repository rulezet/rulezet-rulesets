rule TTP_XOR_MULT_DOSStub_e071 {
  strings:
    $key_e071 = { b4 19 [2] c0 01 [2] 87 03 [2] c0 12 [2] 8e 1e [2] 82 14 [2] 95 1f [2] 8e 51 [2] b3 }

  condition:
    any of them
}