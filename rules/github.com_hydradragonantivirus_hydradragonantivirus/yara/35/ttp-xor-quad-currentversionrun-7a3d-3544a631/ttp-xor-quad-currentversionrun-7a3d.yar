rule TTP_XOR_QUAD_CurrentVersionRun_7a3d {
  strings:
    $key_7a3d = { 29 52 [2] 0d 5c [2] 26 70 [2] 08 52 [2] 1c 49 [2] 13 53 [2] 0d 4e [2] 0f 4f [2] 14 49 [2] 08 4e [2] 14 61 }

  condition:
    any of them
}