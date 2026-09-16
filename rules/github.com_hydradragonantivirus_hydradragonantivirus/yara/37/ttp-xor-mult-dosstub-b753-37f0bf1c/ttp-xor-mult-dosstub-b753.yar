rule TTP_XOR_MULT_DOSStub_b753 {
  strings:
    $key_b753 = { e3 3b [2] 97 23 [2] d0 21 [2] 97 30 [2] d9 3c [2] d5 36 [2] c2 3d [2] d9 73 [2] e4 }

  condition:
    any of them
}