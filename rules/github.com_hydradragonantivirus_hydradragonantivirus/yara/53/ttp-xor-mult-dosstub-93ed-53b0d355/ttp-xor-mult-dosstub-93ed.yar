rule TTP_XOR_MULT_DOSStub_93ed {
  strings:
    $key_93ed = { c7 85 [2] b3 9d [2] f4 9f [2] b3 8e [2] fd 82 [2] f1 88 [2] e6 83 [2] fd cd [2] c0 }

  condition:
    any of them
}