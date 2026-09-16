rule TTP_XOR_QUAD_CurrentVersionRun_43ec {
  strings:
    $key_43ec = { 10 83 [2] 34 8d [2] 1f a1 [2] 31 83 [2] 25 98 [2] 2a 82 [2] 34 9f [2] 36 9e [2] 2d 98 [2] 31 9f [2] 2d b0 }

  condition:
    any of them
}