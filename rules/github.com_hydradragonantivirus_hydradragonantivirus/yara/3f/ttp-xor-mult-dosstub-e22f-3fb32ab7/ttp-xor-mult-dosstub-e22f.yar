rule TTP_XOR_MULT_DOSStub_e22f {
  strings:
    $key_e22f = { b6 47 [2] c2 5f [2] 85 5d [2] c2 4c [2] 8c 40 [2] 80 4a [2] 97 41 [2] 8c 0f [2] b1 }

  condition:
    any of them
}