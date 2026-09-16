rule TTP_XOR_MULT_DOSStub_e76b {
  strings:
    $key_e76b = { b3 03 [2] c7 1b [2] 80 19 [2] c7 08 [2] 89 04 [2] 85 0e [2] 92 05 [2] 89 4b [2] b4 }

  condition:
    any of them
}