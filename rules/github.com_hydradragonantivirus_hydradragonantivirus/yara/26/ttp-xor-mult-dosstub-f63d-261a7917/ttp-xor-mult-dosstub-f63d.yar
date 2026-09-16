rule TTP_XOR_MULT_DOSStub_f63d {
  strings:
    $key_f63d = { a2 55 [2] d6 4d [2] 91 4f [2] d6 5e [2] 98 52 [2] 94 58 [2] 83 53 [2] 98 1d [2] a5 }

  condition:
    any of them
}