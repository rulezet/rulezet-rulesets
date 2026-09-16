rule TTP_XOR_MULT_DOSStub_bb93 {
  strings:
    $key_bb93 = { ef fb [2] 9b e3 [2] dc e1 [2] 9b f0 [2] d5 fc [2] d9 f6 [2] ce fd [2] d5 b3 [2] e8 }

  condition:
    any of them
}