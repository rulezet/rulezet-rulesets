rule TTP_XOR_MULT_DOSStub_f053 {
  strings:
    $key_f053 = { a4 3b [2] d0 23 [2] 97 21 [2] d0 30 [2] 9e 3c [2] 92 36 [2] 85 3d [2] 9e 73 [2] a3 }

  condition:
    any of them
}