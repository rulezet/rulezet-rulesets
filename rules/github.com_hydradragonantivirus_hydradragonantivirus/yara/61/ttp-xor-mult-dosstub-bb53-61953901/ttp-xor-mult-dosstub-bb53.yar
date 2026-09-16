rule TTP_XOR_MULT_DOSStub_bb53 {
  strings:
    $key_bb53 = { ef 3b [2] 9b 23 [2] dc 21 [2] 9b 30 [2] d5 3c [2] d9 36 [2] ce 3d [2] d5 73 [2] e8 }

  condition:
    any of them
}