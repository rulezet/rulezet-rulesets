rule TTP_XOR_MULT_DOSStub_988c {
  strings:
    $key_988c = { cc e4 [2] b8 fc [2] ff fe [2] b8 ef [2] f6 e3 [2] fa e9 [2] ed e2 [2] f6 ac [2] cb }

  condition:
    any of them
}