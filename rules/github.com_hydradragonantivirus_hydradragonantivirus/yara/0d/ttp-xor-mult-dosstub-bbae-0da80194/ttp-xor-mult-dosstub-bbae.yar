rule TTP_XOR_MULT_DOSStub_bbae {
  strings:
    $key_bbae = { ef c6 [2] 9b de [2] dc dc [2] 9b cd [2] d5 c1 [2] d9 cb [2] ce c0 [2] d5 8e [2] e8 }

  condition:
    any of them
}