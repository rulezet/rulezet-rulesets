rule TTP_XOR_MULT_DOSStub_e12b {
  strings:
    $key_e12b = { b5 43 [2] c1 5b [2] 86 59 [2] c1 48 [2] 8f 44 [2] 83 4e [2] 94 45 [2] 8f 0b [2] b2 }

  condition:
    any of them
}