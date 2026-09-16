rule TTP_XOR_QUAD_CurrentVersionRun_3019 {
  strings:
    $key_3019 = { 63 76 [2] 47 78 [2] 6c 54 [2] 42 76 [2] 56 6d [2] 59 77 [2] 47 6a [2] 45 6b [2] 5e 6d [2] 42 6a [2] 5e 45 }

  condition:
    any of them
}