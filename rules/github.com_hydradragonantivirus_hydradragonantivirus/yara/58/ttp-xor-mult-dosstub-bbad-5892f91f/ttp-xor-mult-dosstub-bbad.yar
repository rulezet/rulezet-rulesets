rule TTP_XOR_MULT_DOSStub_bbad {
  strings:
    $key_bbad = { ef c5 [2] 9b dd [2] dc df [2] 9b ce [2] d5 c2 [2] d9 c8 [2] ce c3 [2] d5 8d [2] e8 }

  condition:
    any of them
}