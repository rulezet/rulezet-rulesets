rule TTP_XOR_QUAD_CurrentVersionRun_2eda {
  strings:
    $key_2eda = { 7d b5 [2] 59 bb [2] 72 97 [2] 5c b5 [2] 48 ae [2] 47 b4 [2] 59 a9 [2] 5b a8 [2] 40 ae [2] 5c a9 [2] 40 86 }

  condition:
    any of them
}