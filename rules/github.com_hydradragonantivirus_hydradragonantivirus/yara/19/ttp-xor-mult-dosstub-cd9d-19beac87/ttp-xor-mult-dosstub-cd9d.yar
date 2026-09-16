rule TTP_XOR_MULT_DOSStub_cd9d {
  strings:
    $key_cd9d = { 99 f5 [2] ed ed [2] aa ef [2] ed fe [2] a3 f2 [2] af f8 [2] b8 f3 [2] a3 bd [2] 9e }

  condition:
    any of them
}