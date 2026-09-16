rule TTP_XOR_MULT_DOSStub_e858 {
  strings:
    $key_e858 = { bc 30 [2] c8 28 [2] 8f 2a [2] c8 3b [2] 86 37 [2] 8a 3d [2] 9d 36 [2] 86 78 [2] bb }

  condition:
    any of them
}