rule TTP_XOR_QUAD_CurrentVersionRun_5033 {
  strings:
    $key_5033 = { 03 5c [2] 27 52 [2] 0c 7e [2] 22 5c [2] 36 47 [2] 39 5d [2] 27 40 [2] 25 41 [2] 3e 47 [2] 22 40 [2] 3e 6f }

  condition:
    any of them
}