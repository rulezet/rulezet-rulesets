rule TTP_XOR_QUAD_CurrentVersionRun_32ee {
  strings:
    $key_32ee = { 61 81 [2] 45 8f [2] 6e a3 [2] 40 81 [2] 54 9a [2] 5b 80 [2] 45 9d [2] 47 9c [2] 5c 9a [2] 40 9d [2] 5c b2 }

  condition:
    any of them
}