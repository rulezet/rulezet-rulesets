rule TTP_XOR_QUAD_CurrentVersionRun_3a12 {
  strings:
    $key_3a12 = { 69 7d [2] 4d 73 [2] 66 5f [2] 48 7d [2] 5c 66 [2] 53 7c [2] 4d 61 [2] 4f 60 [2] 54 66 [2] 48 61 [2] 54 4e }

  condition:
    any of them
}