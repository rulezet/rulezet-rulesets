rule TTP_XOR_QUAD_CurrentVersionRun_eb3d {
  strings:
    $key_eb3d = { b8 52 [2] 9c 5c [2] b7 70 [2] 99 52 [2] 8d 49 [2] 82 53 [2] 9c 4e [2] 9e 4f [2] 85 49 [2] 99 4e [2] 85 61 }

  condition:
    any of them
}