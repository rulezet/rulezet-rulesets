rule TTP_XOR_MULT_DOSStub_bb8c {
  strings:
    $key_bb8c = { ef e4 [2] 9b fc [2] dc fe [2] 9b ef [2] d5 e3 [2] d9 e9 [2] ce e2 [2] d5 ac [2] e8 }

  condition:
    any of them
}