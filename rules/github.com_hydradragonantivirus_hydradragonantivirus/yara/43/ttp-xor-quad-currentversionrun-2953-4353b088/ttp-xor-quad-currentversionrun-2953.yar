rule TTP_XOR_QUAD_CurrentVersionRun_2953 {
  strings:
    $key_2953 = { 7a 3c [2] 5e 32 [2] 75 1e [2] 5b 3c [2] 4f 27 [2] 40 3d [2] 5e 20 [2] 5c 21 [2] 47 27 [2] 5b 20 [2] 47 0f }

  condition:
    any of them
}