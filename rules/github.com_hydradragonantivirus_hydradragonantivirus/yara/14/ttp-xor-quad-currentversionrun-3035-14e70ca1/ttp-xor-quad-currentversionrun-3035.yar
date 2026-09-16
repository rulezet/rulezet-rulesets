rule TTP_XOR_QUAD_CurrentVersionRun_3035 {
  strings:
    $key_3035 = { 63 5a [2] 47 54 [2] 6c 78 [2] 42 5a [2] 56 41 [2] 59 5b [2] 47 46 [2] 45 47 [2] 5e 41 [2] 42 46 [2] 5e 69 }

  condition:
    any of them
}