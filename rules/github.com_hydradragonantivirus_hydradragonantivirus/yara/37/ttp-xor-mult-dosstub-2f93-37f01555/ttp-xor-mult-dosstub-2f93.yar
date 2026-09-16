rule TTP_XOR_MULT_DOSStub_2f93 {
  strings:
    $key_2f93 = { 7b fb [2] 0f e3 [2] 48 e1 [2] 0f f0 [2] 41 fc [2] 4d f6 [2] 5a fd [2] 41 b3 [2] 7c }

  condition:
    any of them
}