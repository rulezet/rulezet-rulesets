rule TTP_XOR_MULT_DOSStub_b353 {
  strings:
    $key_b353 = { e7 3b [2] 93 23 [2] d4 21 [2] 93 30 [2] dd 3c [2] d1 36 [2] c6 3d [2] dd 73 [2] e0 }

  condition:
    any of them
}