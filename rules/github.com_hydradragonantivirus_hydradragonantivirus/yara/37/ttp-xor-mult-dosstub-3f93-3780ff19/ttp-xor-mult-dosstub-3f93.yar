rule TTP_XOR_MULT_DOSStub_3f93 {
  strings:
    $key_3f93 = { 6b fb [2] 1f e3 [2] 58 e1 [2] 1f f0 [2] 51 fc [2] 5d f6 [2] 4a fd [2] 51 b3 [2] 6c }

  condition:
    any of them
}