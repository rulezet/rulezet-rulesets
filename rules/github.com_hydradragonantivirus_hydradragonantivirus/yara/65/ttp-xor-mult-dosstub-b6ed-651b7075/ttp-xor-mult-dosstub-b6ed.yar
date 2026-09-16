rule TTP_XOR_MULT_DOSStub_b6ed {
  strings:
    $key_b6ed = { e2 85 [2] 96 9d [2] d1 9f [2] 96 8e [2] d8 82 [2] d4 88 [2] c3 83 [2] d8 cd [2] e5 }

  condition:
    any of them
}