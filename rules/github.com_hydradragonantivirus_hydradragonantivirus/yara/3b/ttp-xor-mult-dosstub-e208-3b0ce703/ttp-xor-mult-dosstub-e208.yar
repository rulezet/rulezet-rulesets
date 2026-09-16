rule TTP_XOR_MULT_DOSStub_e208 {
  strings:
    $key_e208 = { b6 60 [2] c2 78 [2] 85 7a [2] c2 6b [2] 8c 67 [2] 80 6d [2] 97 66 [2] 8c 28 [2] b1 }

  condition:
    any of them
}