rule TTP_XOR_MULT_DOSStub_820c {
  strings:
    $key_820c = { d6 64 [2] a2 7c [2] e5 7e [2] a2 6f [2] ec 63 [2] e0 69 [2] f7 62 [2] ec 2c [2] d1 }

  condition:
    any of them
}