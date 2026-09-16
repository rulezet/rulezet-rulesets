rule TTP_XOR_MULT_DOSStub_c52a {
  strings:
    $key_c52a = { 91 42 [2] e5 5a [2] a2 58 [2] e5 49 [2] ab 45 [2] a7 4f [2] b0 44 [2] ab 0a [2] 96 }

  condition:
    any of them
}