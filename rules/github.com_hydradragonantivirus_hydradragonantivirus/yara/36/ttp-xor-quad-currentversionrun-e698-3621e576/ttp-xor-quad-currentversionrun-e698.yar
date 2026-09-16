rule TTP_XOR_QUAD_CurrentVersionRun_e698 {
  strings:
    $key_e698 = { b5 f7 [2] 91 f9 [2] ba d5 [2] 94 f7 [2] 80 ec [2] 8f f6 [2] 91 eb [2] 93 ea [2] 88 ec [2] 94 eb [2] 88 c4 }

  condition:
    any of them
}