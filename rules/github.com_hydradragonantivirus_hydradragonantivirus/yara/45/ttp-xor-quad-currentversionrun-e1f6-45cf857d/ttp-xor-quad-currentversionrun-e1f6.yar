rule TTP_XOR_QUAD_CurrentVersionRun_e1f6 {
  strings:
    $key_e1f6 = { b2 99 [2] 96 97 [2] bd bb [2] 93 99 [2] 87 82 [2] 88 98 [2] 96 85 [2] 94 84 [2] 8f 82 [2] 93 85 [2] 8f aa }

  condition:
    any of them
}