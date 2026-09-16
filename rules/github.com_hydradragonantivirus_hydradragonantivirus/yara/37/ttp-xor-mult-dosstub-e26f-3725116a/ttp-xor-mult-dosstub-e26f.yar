rule TTP_XOR_MULT_DOSStub_e26f {
  strings:
    $key_e26f = { b6 07 [2] c2 1f [2] 85 1d [2] c2 0c [2] 8c 00 [2] 80 0a [2] 97 01 [2] 8c 4f [2] b1 }

  condition:
    any of them
}