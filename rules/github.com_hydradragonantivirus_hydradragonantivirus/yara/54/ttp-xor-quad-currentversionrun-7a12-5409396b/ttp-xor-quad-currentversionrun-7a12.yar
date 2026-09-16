rule TTP_XOR_QUAD_CurrentVersionRun_7a12 {
  strings:
    $key_7a12 = { 29 7d [2] 0d 73 [2] 26 5f [2] 08 7d [2] 1c 66 [2] 13 7c [2] 0d 61 [2] 0f 60 [2] 14 66 [2] 08 61 [2] 14 4e }

  condition:
    any of them
}