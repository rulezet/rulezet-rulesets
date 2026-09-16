rule TTP_XOR_QUAD_CurrentVersionRun_4b53 {
  strings:
    $key_4b53 = { 18 3c [2] 3c 32 [2] 17 1e [2] 39 3c [2] 2d 27 [2] 22 3d [2] 3c 20 [2] 3e 21 [2] 25 27 [2] 39 20 [2] 25 0f }

  condition:
    any of them
}