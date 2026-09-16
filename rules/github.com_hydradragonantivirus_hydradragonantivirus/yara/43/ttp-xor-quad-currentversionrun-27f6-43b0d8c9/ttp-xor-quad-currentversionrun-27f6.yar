rule TTP_XOR_QUAD_CurrentVersionRun_27f6 {
  strings:
    $key_27f6 = { 74 99 [2] 50 97 [2] 7b bb [2] 55 99 [2] 41 82 [2] 4e 98 [2] 50 85 [2] 52 84 [2] 49 82 [2] 55 85 [2] 49 aa }

  condition:
    any of them
}