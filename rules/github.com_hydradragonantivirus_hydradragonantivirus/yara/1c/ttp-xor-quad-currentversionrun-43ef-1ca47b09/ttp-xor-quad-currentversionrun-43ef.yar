rule TTP_XOR_QUAD_CurrentVersionRun_43ef {
  strings:
    $key_43ef = { 10 80 [2] 34 8e [2] 1f a2 [2] 31 80 [2] 25 9b [2] 2a 81 [2] 34 9c [2] 36 9d [2] 2d 9b [2] 31 9c [2] 2d b3 }

  condition:
    any of them
}