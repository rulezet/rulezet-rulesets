rule TTP_XOR_QUAD_CurrentVersionRun_2c9f {
  strings:
    $key_2c9f = { 7f f0 [2] 5b fe [2] 70 d2 [2] 5e f0 [2] 4a eb [2] 45 f1 [2] 5b ec [2] 59 ed [2] 42 eb [2] 5e ec [2] 42 c3 }

  condition:
    any of them
}