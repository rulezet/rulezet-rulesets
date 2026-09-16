rule TTP_XOR_QUAD_CurrentVersionRun_7e12 {
  strings:
    $key_7e12 = { 2d 7d [2] 09 73 [2] 22 5f [2] 0c 7d [2] 18 66 [2] 17 7c [2] 09 61 [2] 0b 60 [2] 10 66 [2] 0c 61 [2] 10 4e }

  condition:
    any of them
}