rule TTP_XOR_QUAD_CurrentVersionRun_0c3d {
  strings:
    $key_0c3d = { 5f 52 [2] 7b 5c [2] 50 70 [2] 7e 52 [2] 6a 49 [2] 65 53 [2] 7b 4e [2] 79 4f [2] 62 49 [2] 7e 4e [2] 62 61 }

  condition:
    any of them
}