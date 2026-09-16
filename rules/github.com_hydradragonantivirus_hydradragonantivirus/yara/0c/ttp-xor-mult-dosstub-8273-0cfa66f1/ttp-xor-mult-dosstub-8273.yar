rule TTP_XOR_MULT_DOSStub_8273 {
  strings:
    $key_8273 = { d6 1b [2] a2 03 [2] e5 01 [2] a2 10 [2] ec 1c [2] e0 16 [2] f7 1d [2] ec 53 [2] d1 }

  condition:
    any of them
}