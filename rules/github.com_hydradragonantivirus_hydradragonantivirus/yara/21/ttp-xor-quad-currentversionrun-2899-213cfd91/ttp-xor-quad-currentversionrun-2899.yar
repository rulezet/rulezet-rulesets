rule TTP_XOR_QUAD_CurrentVersionRun_2899 {
  strings:
    $key_2899 = { 7b f6 [2] 5f f8 [2] 74 d4 [2] 5a f6 [2] 4e ed [2] 41 f7 [2] 5f ea [2] 5d eb [2] 46 ed [2] 5a ea [2] 46 c5 }

  condition:
    any of them
}