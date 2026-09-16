rule TTP_XOR_MULT_DOSStub_f66b {
  strings:
    $key_f66b = { a2 03 [2] d6 1b [2] 91 19 [2] d6 08 [2] 98 04 [2] 94 0e [2] 83 05 [2] 98 4b [2] a5 }

  condition:
    any of them
}