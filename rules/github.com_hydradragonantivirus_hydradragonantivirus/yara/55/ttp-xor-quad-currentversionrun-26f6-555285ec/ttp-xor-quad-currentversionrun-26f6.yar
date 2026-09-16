rule TTP_XOR_QUAD_CurrentVersionRun_26f6 {
  strings:
    $key_26f6 = { 75 99 [2] 51 97 [2] 7a bb [2] 54 99 [2] 40 82 [2] 4f 98 [2] 51 85 [2] 53 84 [2] 48 82 [2] 54 85 [2] 48 aa }

  condition:
    any of them
}