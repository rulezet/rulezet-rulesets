rule TTP_XOR_QUAD_CurrentVersionRun_307b {
  strings:
    $key_307b = { 63 14 [2] 47 1a [2] 6c 36 [2] 42 14 [2] 56 0f [2] 59 15 [2] 47 08 [2] 45 09 [2] 5e 0f [2] 42 08 [2] 5e 27 }

  condition:
    any of them
}