rule TTP_XOR_MULT_DOSStub_82f9 {
  strings:
    $key_82f9 = { d6 91 [2] a2 89 [2] e5 8b [2] a2 9a [2] ec 96 [2] e0 9c [2] f7 97 [2] ec d9 [2] d1 }

  condition:
    any of them
}