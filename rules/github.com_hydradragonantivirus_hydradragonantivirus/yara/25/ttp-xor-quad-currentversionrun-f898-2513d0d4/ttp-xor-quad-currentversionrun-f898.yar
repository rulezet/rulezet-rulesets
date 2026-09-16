rule TTP_XOR_QUAD_CurrentVersionRun_f898 {
  strings:
    $key_f898 = { ab f7 [2] 8f f9 [2] a4 d5 [2] 8a f7 [2] 9e ec [2] 91 f6 [2] 8f eb [2] 8d ea [2] 96 ec [2] 8a eb [2] 96 c4 }

  condition:
    any of them
}