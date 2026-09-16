rule TTP_XOR_QUAD_CurrentVersionRun_6a3d {
  strings:
    $key_6a3d = { 39 52 [2] 1d 5c [2] 36 70 [2] 18 52 [2] 0c 49 [2] 03 53 [2] 1d 4e [2] 1f 4f [2] 04 49 [2] 18 4e [2] 04 61 }

  condition:
    any of them
}