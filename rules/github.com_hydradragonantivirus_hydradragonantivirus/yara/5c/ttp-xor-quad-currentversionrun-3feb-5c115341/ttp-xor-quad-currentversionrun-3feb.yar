rule TTP_XOR_QUAD_CurrentVersionRun_3feb {
  strings:
    $key_3feb = { 6c 84 [2] 48 8a [2] 63 a6 [2] 4d 84 [2] 59 9f [2] 56 85 [2] 48 98 [2] 4a 99 [2] 51 9f [2] 4d 98 [2] 51 b7 }

  condition:
    any of them
}