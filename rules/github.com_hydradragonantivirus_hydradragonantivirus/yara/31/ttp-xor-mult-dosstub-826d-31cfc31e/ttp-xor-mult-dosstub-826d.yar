rule TTP_XOR_MULT_DOSStub_826d {
  strings:
    $key_826d = { d6 05 [2] a2 1d [2] e5 1f [2] a2 0e [2] ec 02 [2] e0 08 [2] f7 03 [2] ec 4d [2] d1 }

  condition:
    any of them
}