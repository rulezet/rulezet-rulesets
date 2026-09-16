rule TTP_XOR_MULT_DOSStub_e023 {
  strings:
    $key_e023 = { b4 4b [2] c0 53 [2] 87 51 [2] c0 40 [2] 8e 4c [2] 82 46 [2] 95 4d [2] 8e 03 [2] b3 }

  condition:
    any of them
}