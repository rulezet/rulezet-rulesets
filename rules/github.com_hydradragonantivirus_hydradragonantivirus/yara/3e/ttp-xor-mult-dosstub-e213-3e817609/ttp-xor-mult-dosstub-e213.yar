rule TTP_XOR_MULT_DOSStub_e213 {
  strings:
    $key_e213 = { b6 7b [2] c2 63 [2] 85 61 [2] c2 70 [2] 8c 7c [2] 80 76 [2] 97 7d [2] 8c 33 [2] b1 }

  condition:
    any of them
}