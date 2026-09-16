rule TTP_XOR_MULT_DOSStub_e223 {
  strings:
    $key_e223 = { b6 4b [2] c2 53 [2] 85 51 [2] c2 40 [2] 8c 4c [2] 80 46 [2] 97 4d [2] 8c 03 [2] b1 }

  condition:
    any of them
}