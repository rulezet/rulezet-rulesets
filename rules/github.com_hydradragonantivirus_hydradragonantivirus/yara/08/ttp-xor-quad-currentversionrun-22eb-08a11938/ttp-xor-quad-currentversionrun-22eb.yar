rule TTP_XOR_QUAD_CurrentVersionRun_22eb {
  strings:
    $key_22eb = { 71 84 [2] 55 8a [2] 7e a6 [2] 50 84 [2] 44 9f [2] 4b 85 [2] 55 98 [2] 57 99 [2] 4c 9f [2] 50 98 [2] 4c b7 }

  condition:
    any of them
}