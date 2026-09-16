rule TTP_XOR_MULT_DOSStub_f60b {
  strings:
    $key_f60b = { a2 63 [2] d6 7b [2] 91 79 [2] d6 68 [2] 98 64 [2] 94 6e [2] 83 65 [2] 98 2b [2] a5 }

  condition:
    any of them
}