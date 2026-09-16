rule TTP_XOR_MULT_DOSStub_699d {
  strings:
    $key_699d = { 3d f5 [2] 49 ed [2] 0e ef [2] 49 fe [2] 07 f2 [2] 0b f8 [2] 1c f3 [2] 07 bd [2] 3a }

  condition:
    any of them
}