rule TTP_XOR_QUAD_CurrentVersionRun_3c3d {
  strings:
    $key_3c3d = { 6f 52 [2] 4b 5c [2] 60 70 [2] 4e 52 [2] 5a 49 [2] 55 53 [2] 4b 4e [2] 49 4f [2] 52 49 [2] 4e 4e [2] 52 61 }

  condition:
    any of them
}