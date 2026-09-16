rule TTP_XOR_MULT_DOSStub_e33b {
  strings:
    $key_e33b = { b7 53 [2] c3 4b [2] 84 49 [2] c3 58 [2] 8d 54 [2] 81 5e [2] 96 55 [2] 8d 1b [2] b0 }

  condition:
    any of them
}