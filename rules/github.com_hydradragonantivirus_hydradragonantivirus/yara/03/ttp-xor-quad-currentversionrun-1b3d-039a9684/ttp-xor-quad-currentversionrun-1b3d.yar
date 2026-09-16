rule TTP_XOR_QUAD_CurrentVersionRun_1b3d {
  strings:
    $key_1b3d = { 48 52 [2] 6c 5c [2] 47 70 [2] 69 52 [2] 7d 49 [2] 72 53 [2] 6c 4e [2] 6e 4f [2] 75 49 [2] 69 4e [2] 75 61 }

  condition:
    any of them
}