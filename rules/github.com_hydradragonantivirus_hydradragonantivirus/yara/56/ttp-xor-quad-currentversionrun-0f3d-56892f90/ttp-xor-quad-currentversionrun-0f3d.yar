rule TTP_XOR_QUAD_CurrentVersionRun_0f3d {
  strings:
    $key_0f3d = { 5c 52 [2] 78 5c [2] 53 70 [2] 7d 52 [2] 69 49 [2] 66 53 [2] 78 4e [2] 7a 4f [2] 61 49 [2] 7d 4e [2] 61 61 }

  condition:
    any of them
}