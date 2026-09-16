rule TTP_XOR_MULT_DOSStub_e16c {
  strings:
    $key_e16c = { b5 04 [2] c1 1c [2] 86 1e [2] c1 0f [2] 8f 03 [2] 83 09 [2] 94 02 [2] 8f 4c [2] b2 }

  condition:
    any of them
}