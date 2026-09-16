rule TTP_XOR_QUAD_CurrentVersionRun_12eb {
  strings:
    $key_12eb = { 41 84 [2] 65 8a [2] 4e a6 [2] 60 84 [2] 74 9f [2] 7b 85 [2] 65 98 [2] 67 99 [2] 7c 9f [2] 60 98 [2] 7c b7 }

  condition:
    any of them
}