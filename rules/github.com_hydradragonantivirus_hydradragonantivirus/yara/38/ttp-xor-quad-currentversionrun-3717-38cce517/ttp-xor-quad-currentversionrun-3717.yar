rule TTP_XOR_QUAD_CurrentVersionRun_3717 {
  strings:
    $key_3717 = { 64 78 [2] 40 76 [2] 6b 5a [2] 45 78 [2] 51 63 [2] 5e 79 [2] 40 64 [2] 42 65 [2] 59 63 [2] 45 64 [2] 59 4b }

  condition:
    any of them
}