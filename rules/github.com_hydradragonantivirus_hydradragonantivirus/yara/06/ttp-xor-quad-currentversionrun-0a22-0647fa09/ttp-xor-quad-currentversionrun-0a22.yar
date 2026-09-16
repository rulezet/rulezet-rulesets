rule TTP_XOR_QUAD_CurrentVersionRun_0a22 {
  strings:
    $key_0a22 = { 59 4d [2] 7d 43 [2] 56 6f [2] 78 4d [2] 6c 56 [2] 63 4c [2] 7d 51 [2] 7f 50 [2] 64 56 [2] 78 51 [2] 64 7e }

  condition:
    any of them
}