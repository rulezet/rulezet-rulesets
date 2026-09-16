rule TTP_XOR_MULT_DOSStub_bb8a {
  strings:
    $key_bb8a = { ef e2 [2] 9b fa [2] dc f8 [2] 9b e9 [2] d5 e5 [2] d9 ef [2] ce e4 [2] d5 aa [2] e8 }

  condition:
    any of them
}