rule TTP_XOR_MULT_DOSStub_e4ed {
  strings:
    $key_e4ed = { b0 85 [2] c4 9d [2] 83 9f [2] c4 8e [2] 8a 82 [2] 86 88 [2] 91 83 [2] 8a cd [2] b7 }

  condition:
    any of them
}