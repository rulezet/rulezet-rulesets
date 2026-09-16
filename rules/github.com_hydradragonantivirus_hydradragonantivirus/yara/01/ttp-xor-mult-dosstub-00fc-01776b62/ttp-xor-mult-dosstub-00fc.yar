rule TTP_XOR_MULT_DOSStub_00fc {
  strings:
    $key_00fc = { 54 94 [2] 20 8c [2] 67 8e [2] 20 9f [2] 6e 93 [2] 62 99 [2] 75 92 [2] 6e dc [2] 53 }

  condition:
    any of them
}