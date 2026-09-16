rule TTP_XOR_QUAD_CurrentVersionRun_4c3d {
  strings:
    $key_4c3d = { 1f 52 [2] 3b 5c [2] 10 70 [2] 3e 52 [2] 2a 49 [2] 25 53 [2] 3b 4e [2] 39 4f [2] 22 49 [2] 3e 4e [2] 22 61 }

  condition:
    any of them
}