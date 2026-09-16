rule TTP_XOR_MULT_DOSStub_e72b {
  strings:
    $key_e72b = { b3 43 [2] c7 5b [2] 80 59 [2] c7 48 [2] 89 44 [2] 85 4e [2] 92 45 [2] 89 0b [2] b4 }

  condition:
    any of them
}