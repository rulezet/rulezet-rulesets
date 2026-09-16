rule TTP_XOR_MULT_DOSStub_0f93 {
  strings:
    $key_0f93 = { 5b fb [2] 2f e3 [2] 68 e1 [2] 2f f0 [2] 61 fc [2] 6d f6 [2] 7a fd [2] 61 b3 [2] 5c }

  condition:
    any of them
}