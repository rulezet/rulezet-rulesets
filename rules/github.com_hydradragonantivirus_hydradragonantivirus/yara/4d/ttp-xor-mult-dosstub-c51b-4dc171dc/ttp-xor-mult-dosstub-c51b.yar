rule TTP_XOR_MULT_DOSStub_c51b {
  strings:
    $key_c51b = { 91 73 [2] e5 6b [2] a2 69 [2] e5 78 [2] ab 74 [2] a7 7e [2] b0 75 [2] ab 3b [2] 96 }

  condition:
    any of them
}