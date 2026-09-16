rule TTP_XOR_QUAD_CurrentVersionRun_2612 {
  strings:
    $key_2612 = { 75 7d [2] 51 73 [2] 7a 5f [2] 54 7d [2] 40 66 [2] 4f 7c [2] 51 61 [2] 53 60 [2] 48 66 [2] 54 61 [2] 48 4e }

  condition:
    any of them
}