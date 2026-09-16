rule TTP_XOR_MULT_DOSStub_f653 {
  strings:
    $key_f653 = { a2 3b [2] d6 23 [2] 91 21 [2] d6 30 [2] 98 3c [2] 94 36 [2] 83 3d [2] 98 73 [2] a5 }

  condition:
    any of them
}