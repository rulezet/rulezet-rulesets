rule TTP_XOR_QUAD_CurrentVersionRun_0a3d {
  strings:
    $key_0a3d = { 59 52 [2] 7d 5c [2] 56 70 [2] 78 52 [2] 6c 49 [2] 63 53 [2] 7d 4e [2] 7f 4f [2] 64 49 [2] 78 4e [2] 64 61 }

  condition:
    any of them
}