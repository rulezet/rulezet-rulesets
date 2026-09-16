rule TTP_XOR_MULT_DOSStub_277b {
  strings:
    $key_277b = { 73 13 [2] 07 0b [2] 40 09 [2] 07 18 [2] 49 14 [2] 45 1e [2] 52 15 [2] 49 5b [2] 74 }

  condition:
    any of them
}