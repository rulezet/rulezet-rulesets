rule TTP_XOR_QUAD_CurrentVersionRun_fe3d {
  strings:
    $key_fe3d = { ad 52 [2] 89 5c [2] a2 70 [2] 8c 52 [2] 98 49 [2] 97 53 [2] 89 4e [2] 8b 4f [2] 90 49 [2] 8c 4e [2] 90 61 }

  condition:
    any of them
}