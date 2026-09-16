rule TTP_XOR_MULT_DOSStub_8353 {
  strings:
    $key_8353 = { d7 3b [2] a3 23 [2] e4 21 [2] a3 30 [2] ed 3c [2] e1 36 [2] f6 3d [2] ed 73 [2] d0 }

  condition:
    any of them
}