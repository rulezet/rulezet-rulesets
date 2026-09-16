rule TTP_XOR_MULT_DOSStub_f655 {
  strings:
    $key_f655 = { a2 3d [2] d6 25 [2] 91 27 [2] d6 36 [2] 98 3a [2] 94 30 [2] 83 3b [2] 98 75 [2] a5 }

  condition:
    any of them
}