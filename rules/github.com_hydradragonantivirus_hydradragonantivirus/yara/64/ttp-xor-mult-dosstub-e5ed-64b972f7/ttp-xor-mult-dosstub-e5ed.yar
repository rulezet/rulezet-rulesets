rule TTP_XOR_MULT_DOSStub_e5ed {
  strings:
    $key_e5ed = { b1 85 [2] c5 9d [2] 82 9f [2] c5 8e [2] 8b 82 [2] 87 88 [2] 90 83 [2] 8b cd [2] b6 }

  condition:
    any of them
}