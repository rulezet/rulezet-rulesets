rule TTP_XOR_QUAD_CurrentVersionRun_1e3d {
  strings:
    $key_1e3d = { 4d 52 [2] 69 5c [2] 42 70 [2] 6c 52 [2] 78 49 [2] 77 53 [2] 69 4e [2] 6b 4f [2] 70 49 [2] 6c 4e [2] 70 61 }

  condition:
    any of them
}