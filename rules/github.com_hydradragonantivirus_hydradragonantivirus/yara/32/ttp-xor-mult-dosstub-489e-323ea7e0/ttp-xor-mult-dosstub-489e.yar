rule TTP_XOR_MULT_DOSStub_489e {
  strings:
    $key_489e = { 1c f6 [2] 68 ee [2] 2f ec [2] 68 fd [2] 26 f1 [2] 2a fb [2] 3d f0 [2] 26 be [2] 1b }

  condition:
    any of them
}