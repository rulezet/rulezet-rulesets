rule TTP_XOR_MULT_DOSStub_87ea {
  strings:
    $key_87ea = { d3 82 [2] a7 9a [2] e0 98 [2] a7 89 [2] e9 85 [2] e5 8f [2] f2 84 [2] e9 ca [2] d4 }

  condition:
    any of them
}