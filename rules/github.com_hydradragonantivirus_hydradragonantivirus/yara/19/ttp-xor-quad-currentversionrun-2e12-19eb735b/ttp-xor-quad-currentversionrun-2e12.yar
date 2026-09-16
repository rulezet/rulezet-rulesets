rule TTP_XOR_QUAD_CurrentVersionRun_2e12 {
  strings:
    $key_2e12 = { 7d 7d [2] 59 73 [2] 72 5f [2] 5c 7d [2] 48 66 [2] 47 7c [2] 59 61 [2] 5b 60 [2] 40 66 [2] 5c 61 [2] 40 4e }

  condition:
    any of them
}