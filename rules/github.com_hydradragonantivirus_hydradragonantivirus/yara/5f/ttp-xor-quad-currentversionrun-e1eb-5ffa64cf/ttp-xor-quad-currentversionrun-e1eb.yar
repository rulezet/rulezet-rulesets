rule TTP_XOR_QUAD_CurrentVersionRun_e1eb {
  strings:
    $key_e1eb = { b2 84 [2] 96 8a [2] bd a6 [2] 93 84 [2] 87 9f [2] 88 85 [2] 96 98 [2] 94 99 [2] 8f 9f [2] 93 98 [2] 8f b7 }

  condition:
    any of them
}