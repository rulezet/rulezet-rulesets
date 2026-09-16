rule TTP_XOR_MULT_DOSStub_8213 {
  strings:
    $key_8213 = { d6 7b [2] a2 63 [2] e5 61 [2] a2 70 [2] ec 7c [2] e0 76 [2] f7 7d [2] ec 33 [2] d1 }

  condition:
    any of them
}