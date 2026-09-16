rule TTP_XOR_MULT_DOSStub_85ed {
  strings:
    $key_85ed = { d1 85 [2] a5 9d [2] e2 9f [2] a5 8e [2] eb 82 [2] e7 88 [2] f0 83 [2] eb cd [2] d6 }

  condition:
    any of them
}