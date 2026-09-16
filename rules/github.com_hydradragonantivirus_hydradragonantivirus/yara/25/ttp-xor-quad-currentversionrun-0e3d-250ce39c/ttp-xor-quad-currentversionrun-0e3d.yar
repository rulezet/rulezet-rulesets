rule TTP_XOR_QUAD_CurrentVersionRun_0e3d {
  strings:
    $key_0e3d = { 5d 52 [2] 79 5c [2] 52 70 [2] 7c 52 [2] 68 49 [2] 67 53 [2] 79 4e [2] 7b 4f [2] 60 49 [2] 7c 4e [2] 60 61 }

  condition:
    any of them
}