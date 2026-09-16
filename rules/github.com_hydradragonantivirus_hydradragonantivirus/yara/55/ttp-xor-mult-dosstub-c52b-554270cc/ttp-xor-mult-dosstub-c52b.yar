rule TTP_XOR_MULT_DOSStub_c52b {
  strings:
    $key_c52b = { 91 43 [2] e5 5b [2] a2 59 [2] e5 48 [2] ab 44 [2] a7 4e [2] b0 45 [2] ab 0b [2] 96 }

  condition:
    any of them
}