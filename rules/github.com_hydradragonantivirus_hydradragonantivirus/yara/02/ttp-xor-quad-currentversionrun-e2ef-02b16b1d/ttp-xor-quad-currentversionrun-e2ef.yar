rule TTP_XOR_QUAD_CurrentVersionRun_e2ef {
  strings:
    $key_e2ef = { b1 80 [2] 95 8e [2] be a2 [2] 90 80 [2] 84 9b [2] 8b 81 [2] 95 9c [2] 97 9d [2] 8c 9b [2] 90 9c [2] 8c b3 }

  condition:
    any of them
}