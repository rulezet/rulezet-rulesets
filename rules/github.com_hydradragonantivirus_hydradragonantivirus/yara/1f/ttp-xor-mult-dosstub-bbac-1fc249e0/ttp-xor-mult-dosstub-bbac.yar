rule TTP_XOR_MULT_DOSStub_bbac {
  strings:
    $key_bbac = { ef c4 [2] 9b dc [2] dc de [2] 9b cf [2] d5 c3 [2] d9 c9 [2] ce c2 [2] d5 8c [2] e8 }

  condition:
    any of them
}