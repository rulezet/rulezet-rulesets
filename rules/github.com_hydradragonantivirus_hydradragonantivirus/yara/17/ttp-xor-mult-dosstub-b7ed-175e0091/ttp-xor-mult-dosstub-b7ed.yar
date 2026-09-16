rule TTP_XOR_MULT_DOSStub_b7ed {
  strings:
    $key_b7ed = { e3 85 [2] 97 9d [2] d0 9f [2] 97 8e [2] d9 82 [2] d5 88 [2] c2 83 [2] d9 cd [2] e4 }

  condition:
    any of them
}