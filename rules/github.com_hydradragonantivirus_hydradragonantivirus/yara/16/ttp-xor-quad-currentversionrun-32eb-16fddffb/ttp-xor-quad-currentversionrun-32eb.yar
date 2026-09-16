rule TTP_XOR_QUAD_CurrentVersionRun_32eb {
  strings:
    $key_32eb = { 61 84 [2] 45 8a [2] 6e a6 [2] 40 84 [2] 54 9f [2] 5b 85 [2] 45 98 [2] 47 99 [2] 5c 9f [2] 40 98 [2] 5c b7 }

  condition:
    any of them
}