rule TTP_XOR_MULT_DOSStub_cede {
  strings:
    $key_cede = { 9a b6 [2] ee ae [2] a9 ac [2] ee bd [2] a0 b1 [2] ac bb [2] bb b0 [2] a0 fe [2] 9d }

  condition:
    any of them
}