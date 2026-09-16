rule TTP_XOR_QUAD_CurrentVersionRun_e898 {
  strings:
    $key_e898 = { bb f7 [2] 9f f9 [2] b4 d5 [2] 9a f7 [2] 8e ec [2] 81 f6 [2] 9f eb [2] 9d ea [2] 86 ec [2] 9a eb [2] 86 c4 }

  condition:
    any of them
}