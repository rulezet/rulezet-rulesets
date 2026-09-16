rule TTP_XOR_MULT_DOSStub_f651 {
  strings:
    $key_f651 = { a2 39 [2] d6 21 [2] 91 23 [2] d6 32 [2] 98 3e [2] 94 34 [2] 83 3f [2] 98 71 [2] a5 }

  condition:
    any of them
}