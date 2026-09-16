rule TTP_XOR_QUAD_CurrentVersionRun_3232 {
  strings:
    $key_3232 = { 61 5d [2] 45 53 [2] 6e 7f [2] 40 5d [2] 54 46 [2] 5b 5c [2] 45 41 [2] 47 40 [2] 5c 46 [2] 40 41 [2] 5c 6e }

  condition:
    any of them
}