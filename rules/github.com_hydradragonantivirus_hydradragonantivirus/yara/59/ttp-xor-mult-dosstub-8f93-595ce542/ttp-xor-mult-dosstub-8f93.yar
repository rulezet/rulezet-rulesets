rule TTP_XOR_MULT_DOSStub_8f93 {
  strings:
    $key_8f93 = { db fb [2] af e3 [2] e8 e1 [2] af f0 [2] e1 fc [2] ed f6 [2] fa fd [2] e1 b3 [2] dc }

  condition:
    any of them
}