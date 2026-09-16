rule TTP_XOR_MULT_DOSStub_e824 {
  strings:
    $key_e824 = { bc 4c [2] c8 54 [2] 8f 56 [2] c8 47 [2] 86 4b [2] 8a 41 [2] 9d 4a [2] 86 04 [2] bb }

  condition:
    any of them
}