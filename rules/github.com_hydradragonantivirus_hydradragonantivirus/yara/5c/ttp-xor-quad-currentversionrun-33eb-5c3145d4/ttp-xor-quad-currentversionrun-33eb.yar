rule TTP_XOR_QUAD_CurrentVersionRun_33eb {
  strings:
    $key_33eb = { 60 84 [2] 44 8a [2] 6f a6 [2] 41 84 [2] 55 9f [2] 5a 85 [2] 44 98 [2] 46 99 [2] 5d 9f [2] 41 98 [2] 5d b7 }

  condition:
    any of them
}