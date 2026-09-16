rule TTP_XOR_MULT_DOSStub_f671 {
  strings:
    $key_f671 = { a2 19 [2] d6 01 [2] 91 03 [2] d6 12 [2] 98 1e [2] 94 14 [2] 83 1f [2] 98 51 [2] a5 }

  condition:
    any of them
}