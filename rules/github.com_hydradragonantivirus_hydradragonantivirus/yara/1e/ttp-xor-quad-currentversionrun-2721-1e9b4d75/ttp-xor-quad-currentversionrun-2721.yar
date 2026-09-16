rule TTP_XOR_QUAD_CurrentVersionRun_2721 {
  strings:
    $key_2721 = { 74 4e [2] 50 40 [2] 7b 6c [2] 55 4e [2] 41 55 [2] 4e 4f [2] 50 52 [2] 52 53 [2] 49 55 [2] 55 52 [2] 49 7d }

  condition:
    any of them
}