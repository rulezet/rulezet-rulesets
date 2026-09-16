rule TTP_XOR_QUAD_CurrentVersionRun_3fea {
  strings:
    $key_3fea = { 6c 85 [2] 48 8b [2] 63 a7 [2] 4d 85 [2] 59 9e [2] 56 84 [2] 48 99 [2] 4a 98 [2] 51 9e [2] 4d 99 [2] 51 b6 }

  condition:
    any of them
}