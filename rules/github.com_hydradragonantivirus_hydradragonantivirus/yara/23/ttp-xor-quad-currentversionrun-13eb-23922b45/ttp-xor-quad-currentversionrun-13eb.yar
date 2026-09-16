rule TTP_XOR_QUAD_CurrentVersionRun_13eb {
  strings:
    $key_13eb = { 40 84 [2] 64 8a [2] 4f a6 [2] 61 84 [2] 75 9f [2] 7a 85 [2] 64 98 [2] 66 99 [2] 7d 9f [2] 61 98 [2] 7d b7 }

  condition:
    any of them
}