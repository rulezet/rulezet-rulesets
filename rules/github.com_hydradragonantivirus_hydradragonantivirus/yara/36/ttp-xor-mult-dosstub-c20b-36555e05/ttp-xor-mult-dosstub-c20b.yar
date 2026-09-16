rule TTP_XOR_MULT_DOSStub_c20b {
  strings:
    $key_c20b = { 96 63 [2] e2 7b [2] a5 79 [2] e2 68 [2] ac 64 [2] a0 6e [2] b7 65 [2] ac 2b [2] 91 }

  condition:
    any of them
}