rule TTP_XOR_QUAD_CurrentVersionRun_22ee {
  strings:
    $key_22ee = { 71 81 [2] 55 8f [2] 7e a3 [2] 50 81 [2] 44 9a [2] 4b 80 [2] 55 9d [2] 57 9c [2] 4c 9a [2] 50 9d [2] 4c b2 }

  condition:
    any of them
}