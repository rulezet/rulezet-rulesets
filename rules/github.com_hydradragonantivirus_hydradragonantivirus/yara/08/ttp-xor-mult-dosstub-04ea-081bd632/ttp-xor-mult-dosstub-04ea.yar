rule TTP_XOR_MULT_DOSStub_04ea {
  strings:
    $key_04ea = { 50 82 [2] 24 9a [2] 63 98 [2] 24 89 [2] 6a 85 [2] 66 8f [2] 71 84 [2] 6a ca [2] 57 }

  condition:
    any of them
}