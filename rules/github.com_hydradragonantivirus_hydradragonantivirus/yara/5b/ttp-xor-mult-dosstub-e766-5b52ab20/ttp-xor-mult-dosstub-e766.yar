rule TTP_XOR_MULT_DOSStub_e766 {
  strings:
    $key_e766 = { b3 0e [2] c7 16 [2] 80 14 [2] c7 05 [2] 89 09 [2] 85 03 [2] 92 08 [2] 89 46 [2] b4 }

  condition:
    any of them
}