rule TTP_XOR_QUAD_CurrentVersionRun_0f22 {
  strings:
    $key_0f22 = { 5c 4d [2] 78 43 [2] 53 6f [2] 7d 4d [2] 69 56 [2] 66 4c [2] 78 51 [2] 7a 50 [2] 61 56 [2] 7d 51 [2] 61 7e }

  condition:
    any of them
}