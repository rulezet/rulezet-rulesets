rule TTP_XOR_MULT_DOSStub_e267 {
  strings:
    $key_e267 = { b6 0f [2] c2 17 [2] 85 15 [2] c2 04 [2] 8c 08 [2] 80 02 [2] 97 09 [2] 8c 47 [2] b1 }

  condition:
    any of them
}