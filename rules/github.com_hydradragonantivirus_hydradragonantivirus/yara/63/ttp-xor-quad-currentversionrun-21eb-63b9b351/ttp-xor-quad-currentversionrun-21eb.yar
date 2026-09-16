rule TTP_XOR_QUAD_CurrentVersionRun_21eb {
  strings:
    $key_21eb = { 72 84 [2] 56 8a [2] 7d a6 [2] 53 84 [2] 47 9f [2] 48 85 [2] 56 98 [2] 54 99 [2] 4f 9f [2] 53 98 [2] 4f b7 }

  condition:
    any of them
}