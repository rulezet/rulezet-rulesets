rule TTP_XOR_MULT_DOSStub_8211 {
  strings:
    $key_8211 = { d6 79 [2] a2 61 [2] e5 63 [2] a2 72 [2] ec 7e [2] e0 74 [2] f7 7f [2] ec 31 [2] d1 }

  condition:
    any of them
}