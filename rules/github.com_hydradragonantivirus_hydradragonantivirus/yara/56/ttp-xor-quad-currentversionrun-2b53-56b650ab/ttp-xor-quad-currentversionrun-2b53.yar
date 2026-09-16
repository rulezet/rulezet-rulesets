rule TTP_XOR_QUAD_CurrentVersionRun_2b53 {
  strings:
    $key_2b53 = { 78 3c [2] 5c 32 [2] 77 1e [2] 59 3c [2] 4d 27 [2] 42 3d [2] 5c 20 [2] 5e 21 [2] 45 27 [2] 59 20 [2] 45 0f }

  condition:
    any of them
}