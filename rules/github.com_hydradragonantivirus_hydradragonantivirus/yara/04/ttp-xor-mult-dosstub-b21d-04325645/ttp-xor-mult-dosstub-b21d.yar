rule TTP_XOR_MULT_DOSStub_b21d {
  strings:
    $key_b21d = { e6 75 [2] 92 6d [2] d5 6f [2] 92 7e [2] dc 72 [2] d0 78 [2] c7 73 [2] dc 3d [2] e1 }

  condition:
    any of them
}