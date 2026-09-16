rule TTP_XOR_QUAD_CurrentVersionRun_37f6 {
  strings:
    $key_37f6 = { 64 99 [2] 40 97 [2] 6b bb [2] 45 99 [2] 51 82 [2] 5e 98 [2] 40 85 [2] 42 84 [2] 59 82 [2] 45 85 [2] 59 aa }

  condition:
    any of them
}