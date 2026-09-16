rule TTP_XOR_MULT_DOSStub_f100 {
  strings:
    $key_f100 = { a5 68 [2] d1 70 [2] 96 72 [2] d1 63 [2] 9f 6f [2] 93 65 [2] 84 6e [2] 9f 20 [2] a2 }

  condition:
    any of them
}