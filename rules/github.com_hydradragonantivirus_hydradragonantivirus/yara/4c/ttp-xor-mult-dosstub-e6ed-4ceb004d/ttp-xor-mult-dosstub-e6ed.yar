rule TTP_XOR_MULT_DOSStub_e6ed {
  strings:
    $key_e6ed = { b2 85 [2] c6 9d [2] 81 9f [2] c6 8e [2] 88 82 [2] 84 88 [2] 93 83 [2] 88 cd [2] b5 }

  condition:
    any of them
}