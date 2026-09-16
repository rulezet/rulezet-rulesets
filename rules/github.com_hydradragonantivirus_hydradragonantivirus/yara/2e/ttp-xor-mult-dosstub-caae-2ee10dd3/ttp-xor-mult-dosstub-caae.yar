rule TTP_XOR_MULT_DOSStub_caae {
  strings:
    $key_caae = { 9e c6 [2] ea de [2] ad dc [2] ea cd [2] a4 c1 [2] a8 cb [2] bf c0 [2] a4 8e [2] 99 }

  condition:
    any of them
}