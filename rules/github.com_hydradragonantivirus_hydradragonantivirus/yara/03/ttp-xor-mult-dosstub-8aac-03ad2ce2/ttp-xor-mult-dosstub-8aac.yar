rule TTP_XOR_MULT_DOSStub_8aac {
  strings:
    $key_8aac = { de c4 [2] aa dc [2] ed de [2] aa cf [2] e4 c3 [2] e8 c9 [2] ff c2 [2] e4 8c [2] d9 }

  condition:
    any of them
}