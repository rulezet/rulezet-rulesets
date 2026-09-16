rule TTP_XOR_QUAD_CurrentVersionRun_34eb {
  strings:
    $key_34eb = { 67 84 [2] 43 8a [2] 68 a6 [2] 46 84 [2] 52 9f [2] 5d 85 [2] 43 98 [2] 41 99 [2] 5a 9f [2] 46 98 [2] 5a b7 }

  condition:
    any of them
}