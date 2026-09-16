rule TTP_XOR_MULT_DOSStub_ca6c {
  strings:
    $key_ca6c = { 9e 04 [2] ea 1c [2] ad 1e [2] ea 0f [2] a4 03 [2] a8 09 [2] bf 02 [2] a4 4c [2] 99 }

  condition:
    any of them
}