rule TTP_XOR_QUAD_CurrentVersionRun_51eb {
  strings:
    $key_51eb = { 02 84 [2] 26 8a [2] 0d a6 [2] 23 84 [2] 37 9f [2] 38 85 [2] 26 98 [2] 24 99 [2] 3f 9f [2] 23 98 [2] 3f b7 }

  condition:
    any of them
}