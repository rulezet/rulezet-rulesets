rule TTP_XOR_MULT_DOSStub_df9f {
  strings:
    $key_df9f = { 8b f7 [2] ff ef [2] b8 ed [2] ff fc [2] b1 f0 [2] bd fa [2] aa f1 [2] b1 bf [2] 8c }

  condition:
    any of them
}