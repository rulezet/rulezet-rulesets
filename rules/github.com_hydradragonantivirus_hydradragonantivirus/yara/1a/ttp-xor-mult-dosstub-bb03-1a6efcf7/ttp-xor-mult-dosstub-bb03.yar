rule TTP_XOR_MULT_DOSStub_bb03 {
  strings:
    $key_bb03 = { ef 6b [2] 9b 73 [2] dc 71 [2] 9b 60 [2] d5 6c [2] d9 66 [2] ce 6d [2] d5 23 [2] e8 }

  condition:
    any of them
}